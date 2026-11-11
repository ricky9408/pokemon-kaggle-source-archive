from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

from evaluation_v6_3_1.eir_prebinding import eir_canonical_cbor_decode, eir_canonical_cbor_encode


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"
COLLECTOR = "/v631302/bin/v631302-m0-diagnostic-collector"
PRIMARY = "/v631302/src/fixture.cc"
FROZEN_TARGETS = (
    ROOT / "strategy/evaluation_v6_3_1_entropy_static_closure_sourcebound_20260721.json"
)
VALID_CAPTURE_CONTEXT_HEX = eir_canonical_cbor_encode([1, "fixture.cc", []]).hex()


@dataclass(frozen=True)
class DockerBuild:
    docker: str
    work: Path


@dataclass(frozen=True)
class FreshWorkerBuild:
    docker: str
    work: Path


@dataclass(frozen=True)
class CollectorCapture:
    result: subprocess.CompletedProcess[bytes]
    receipt: bytes
    write_trace: bytes = b""


def _checked(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode == 0, (
        f"command failed ({result.returncode}): {command!r}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    return result


def _build_collector(
    docker: str, work: Path, *, structural_test_hooks: bool = False
) -> DockerBuild:
    prefix = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
        "-v",
        f"{ROOT}:/src:ro",
        "-v",
        f"{work}:/work:rw",
        "-w",
        "/work",
        IMAGE,
    ]
    configure = prefix + [
        "cmake",
        "-S",
        "/src/evaluation_v6_3_1/native/m0_diagnostic_collector",
        "-B",
        "/work/build",
        "-G",
        "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
    ]
    if structural_test_hooks:
        configure.append("-DV631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS=ON")
    _checked(configure)
    _checked(
        prefix
        + [
            "cmake",
            "--build",
            "/work/build",
            "--target",
            "v631302-m0-diagnostic-collector",
            "--",
            "-j2",
        ]
    )
    _checked(
        prefix
        + [
            "clang",
            "-std=c11",
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-o",
            "/work/build/bin/v631302-write-trace-interposer.so",
            "/src/tests/fixtures/evaluation_v6_3_1/m0_diagnostic_collector/write_trace_interposer.c",
        ]
    )
    assert (work / "build/bin/v631302-m0-diagnostic-collector").is_file()
    assert (work / "build/bin/v631302-write-trace-interposer.so").is_file()
    return DockerBuild(docker=docker, work=work)


def _build_fresh_worker(
    docker: str, work: Path, worker_fixture: str = "v631302_diagnostic_worker_v1.py"
) -> FreshWorkerBuild:
    fixture = ROOT / "tests/fixtures/evaluation_v6_3_1/m0_diagnostic_collector/worker"
    work.mkdir()
    shutil.copyfile(fixture / worker_fixture, work / "bootstrap.py")
    prefix = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
        "-v",
        f"{ROOT}:/src:ro",
        "-v",
        f"{work}:/work:rw",
        "-w",
        "/work",
        IMAGE,
    ]
    _checked(
        prefix
        + [
            "cmake",
            "-S",
            "/src/evaluation_v6_3_1/native/m0_diagnostic_collector",
            "-B",
            "/work/build",
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DV631302_M0_DIAGNOSTIC_ENABLE_TEST_BOOTSTRAP=ON",
            "-DV631302_M0_DIAGNOSTIC_TEST_BOOTSTRAP_PATH=/work/bootstrap.py",
        ]
    )
    _checked(
        prefix
        + [
            "cmake",
            "--build",
            "/work/build",
            "--target",
            "v631302-m0-diagnostic-fresh-worker",
            "--",
            "-j2",
        ]
    )
    assert (work / "build/bin/v631302-m0-diagnostic-fresh-worker").is_file()
    return FreshWorkerBuild(docker=docker, work=work)


@pytest.fixture(scope="module")
def docker_build(tmp_path_factory: pytest.TempPathFactory) -> DockerBuild:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 diagnostic collector test")
    image = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if image.returncode != 0 or image.stdout.strip() != b"amd64":
        pytest.skip("the pinned Linux/amd64 Clang 16 image is unavailable")
    return _build_collector(docker, tmp_path_factory.mktemp("m0-diagnostic-collector"))


@pytest.fixture(scope="module")
def docker_structural_build(
    docker_build: DockerBuild, tmp_path_factory: pytest.TempPathFactory
) -> DockerBuild:
    return _build_collector(
        docker_build.docker,
        tmp_path_factory.mktemp("m0-diagnostic-structural-contract"),
        structural_test_hooks=True,
    )


def _run(
    context: DockerBuild,
    *,
    primary: str = PRIMARY,
    compiler_arguments: tuple[str, ...] = (
        "-std=c++20",
        "-fsyntax-only",
        "-nostdinc",
        "-I",
        "/v631302/src",
    ),
    collector_arguments: tuple[str, ...] = (),
    no_fd3_receipt: bool = False,
    missing_fd3: bool = False,
    regular_fd3: bool = False,
    capture_context_hex: str = VALID_CAPTURE_CONTEXT_HEX,
) -> subprocess.CompletedProcess[bytes]:
    return _run_capture(
        context,
        primary=primary,
        compiler_arguments=compiler_arguments,
        collector_arguments=collector_arguments,
        no_fd3_receipt=no_fd3_receipt,
        missing_fd3=missing_fd3,
        regular_fd3=regular_fd3,
        capture_context_hex=capture_context_hex,
    ).result


def _run_capture(
    context: DockerBuild,
    *,
    primary: str = PRIMARY,
    compiler_arguments: tuple[str, ...] = (
        "-std=c++20",
        "-fsyntax-only",
        "-nostdinc",
        "-I",
        "/v631302/src",
    ),
    collector_arguments: tuple[str, ...] = (),
    no_fd3_receipt: bool = False,
    missing_fd3: bool = False,
    regular_fd3: bool = False,
    capture_context_hex: str = VALID_CAPTURE_CONTEXT_HEX,
    trace_fd3_writes: bool = False,
) -> CollectorCapture:
    assert sum((no_fd3_receipt, missing_fd3, regular_fd3)) <= 1
    fixture = ROOT / "tests/fixtures/evaluation_v6_3_1/m0_diagnostic_collector"
    collector_command = [
        COLLECTOR,
        "--protocol=631302",
        "--level=2",
        f"--primary-source={primary}",
        *collector_arguments,
    ]
    if no_fd3_receipt:
        collector_command.append("--test-no-fd3-receipt")
    else:
        collector_command.append(
            f"--capture-context-v1-cbor-hex={capture_context_hex}"
        )
    collector_command.extend(["--", *compiler_arguments])

    docker_prefix = [
        context.docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "-e",
        "LD_LIBRARY_PATH=/opt/llvm-build/lib",
        "-v",
        f"{fixture}:/v631302/src:ro",
        "-v",
        f"{context.work / 'build/bin'}:/v631302/bin:ro",
        "-w",
        "/v631302/work",
    ]
    if no_fd3_receipt or missing_fd3:
        result = subprocess.run(
            [*docker_prefix, IMAGE, *collector_command],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return CollectorCapture(result=result, receipt=b"")

    capture_dir = context.work / "receipt-captures" / uuid.uuid4().hex
    capture_dir.mkdir(parents=True)
    if regular_fd3:
        regular_script = """
set +e
"$@" 3>/v631302/out/receipt.bin 1>/v631302/out/stdout.bin 2>/v631302/out/stderr.bin
status=$?
printf '%s\n' "$status" >/v631302/out/status.txt
exit 0
"""
        infrastructure = subprocess.run(
            [
                *docker_prefix,
                "-v",
                f"{capture_dir}:/v631302/out:rw",
                IMAGE,
                "/bin/sh",
                "-c",
                regular_script,
                "v631302-regular-fd3-harness",
                *collector_command,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        status_path = capture_dir / "status.txt"
        if infrastructure.returncode != 0 or not status_path.is_file():
            return CollectorCapture(result=infrastructure, receipt=b"")
        result = subprocess.CompletedProcess(
            args=infrastructure.args,
            returncode=int(status_path.read_text(encoding="ascii").strip()),
            stdout=(capture_dir / "stdout.bin").read_bytes(),
            stderr=(capture_dir / "stderr.bin").read_bytes(),
        )
        return CollectorCapture(
            result=result,
            receipt=(capture_dir / "receipt.bin").read_bytes(),
        )

    receipt_script = """
set +e
(
  "$@" 3>&1 1>/v631302/out/stdout.bin 2>/v631302/out/stderr.bin
  status=$?
  printf '%s\n' "$status" >/v631302/out/status.txt
) | cat >/v631302/out/receipt.bin
exit 0
"""
    if trace_fd3_writes:
        receipt_script = """
set +e
(
  LD_PRELOAD=/v631302/bin/v631302-write-trace-interposer.so \
    "$@" 4>/v631302/out/write-trace.bin \
    3>&1 1>/v631302/out/stdout.bin 2>/v631302/out/stderr.bin
  status=$?
  printf '%s\n' "$status" >/v631302/out/status.txt
) | cat >/v631302/out/receipt.bin
exit 0
"""
    infrastructure = subprocess.run(
        [
            *docker_prefix,
            "-v",
            f"{capture_dir}:/v631302/out:rw",
            IMAGE,
            "/bin/sh",
            "-c",
            receipt_script,
            "v631302-receipt-harness",
            *collector_command,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    status_path = capture_dir / "status.txt"
    if infrastructure.returncode != 0 or not status_path.is_file():
        return CollectorCapture(result=infrastructure, receipt=b"")
    result = subprocess.CompletedProcess(
        args=infrastructure.args,
        returncode=int(status_path.read_text(encoding="ascii").strip()),
        stdout=(capture_dir / "stdout.bin").read_bytes(),
        stderr=(capture_dir / "stderr.bin").read_bytes(),
    )
    trace_path = capture_dir / "write-trace.bin"
    return CollectorCapture(
        result=result,
        receipt=(capture_dir / "receipt.bin").read_bytes(),
        write_trace=trace_path.read_bytes() if trace_path.is_file() else b"",
    )


def _decode_receipt_stream(stream: bytes) -> list[list[object]]:
    events: list[list[object]] = []
    cursor = 0
    while cursor < len(stream):
        assert len(stream) - cursor >= 16
        assert stream[cursor : cursor + 8] == b"V631CR01"
        payload_length = int.from_bytes(stream[cursor + 8 : cursor + 16], "big")
        cursor += 16
        assert payload_length <= len(stream) - cursor
        payload = stream[cursor : cursor + payload_length]
        cursor += payload_length
        event = eir_canonical_cbor_decode(payload)
        assert eir_canonical_cbor_encode(event) == payload
        assert isinstance(event, list)
        events.append(event)
    assert cursor == len(stream)
    return events


def _receipt_frame_spans(stream: bytes) -> list[tuple[int, int, list[object]]]:
    spans: list[tuple[int, int, list[object]]] = []
    cursor = 0
    while cursor < len(stream):
        start = cursor
        assert len(stream) - cursor >= 16
        assert stream[cursor : cursor + 8] == b"V631CR01"
        payload_length = int.from_bytes(stream[cursor + 8 : cursor + 16], "big")
        cursor += 16
        assert payload_length <= len(stream) - cursor
        payload = stream[cursor : cursor + payload_length]
        cursor += payload_length
        event = eir_canonical_cbor_decode(payload)
        assert isinstance(event, list)
        spans.append((start, cursor, event))
    assert cursor == len(stream)
    return spans


def _decode_write_trace(trace: bytes) -> list[tuple[int, int]]:
    assert trace and len(trace) % 24 == 0
    records: list[tuple[int, int]] = []
    for offset in range(0, len(trace), 24):
        record = trace[offset : offset + 24]
        assert record[:8] == b"V631WT01"
        requested = int.from_bytes(record[8:16], "big")
        result = int.from_bytes(record[16:24], "big")
        assert result != (1 << 64) - 1
        assert 0 < result <= requested
        records.append((requested, result))
    return records


def _run_peer_observed_capture(
    context: DockerBuild,
) -> tuple[CollectorCapture, dict[str, object]]:
    fixture = ROOT / "tests/fixtures/evaluation_v6_3_1/m0_diagnostic_collector"
    capture_dir = context.work / "peer-observed-captures" / uuid.uuid4().hex
    capture_dir.mkdir(parents=True)
    collector_command = [
        COLLECTOR,
        "--protocol=631302",
        "--level=2",
        f"--primary-source={PRIMARY}",
        f"--capture-context-v1-cbor-hex={VALID_CAPTURE_CONTEXT_HEX}",
        "--",
        "-std=c++20",
        "-fsyntax-only",
        "-nostdinc",
        "-I",
        "/v631302/src",
    ]
    infrastructure = subprocess.run(
        [
            context.docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "-e",
            "LD_LIBRARY_PATH=/opt/llvm-build/lib",
            "-v",
            f"{fixture}:/v631302/src:ro",
            "-v",
            f"{context.work / 'build/bin'}:/v631302/bin:ro",
            "-v",
            f"{capture_dir}:/v631302/out:rw",
            "-w",
            "/v631302/work",
            IMAGE,
            "python3",
            "/v631302/src/receipt_test_launcher.py",
            "/v631302/out",
            "--",
            *collector_command,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert infrastructure.returncode == 0, (
        infrastructure.stdout,
        infrastructure.stderr,
    )
    result = subprocess.CompletedProcess(
        args=infrastructure.args,
        returncode=int((capture_dir / "status.txt").read_text(encoding="ascii").strip()),
        stdout=(capture_dir / "stdout.bin").read_bytes(),
        stderr=(capture_dir / "stderr.bin").read_bytes(),
    )
    metadata = json.loads((capture_dir / "peer.json").read_text(encoding="ascii"))
    assert isinstance(metadata, dict)
    return (
        CollectorCapture(
            result=result,
            receipt=(capture_dir / "receipt.bin").read_bytes(),
        ),
        metadata,
    )


def _run_fresh_worker(
    context: FreshWorkerBuild, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    command = [
        context.docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
        "-e",
        "LD_LIBRARY_PATH=/opt/llvm-build/lib",
    ]
    for key, value in (environment or {}).items():
        command.extend(["-e", f"{key}={value}"])
    command.extend(
        [
            "-v",
            f"{context.work}:/work:rw",
            IMAGE,
            "/work/build/bin/v631302-m0-diagnostic-fresh-worker",
            "--test-bootstrap",
        ]
    )
    return subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _run_prelaunch_profile(
    context: FreshWorkerBuild, tamper: str = "none"
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            context.docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "-e",
            "LD_LIBRARY_PATH=/opt/llvm-build/lib",
            "-v",
            f"{context.work}:/work:rw",
            IMAGE,
            "/work/build/bin/v631302-m0-diagnostic-fresh-worker",
            f"--test-prelaunch-profile={tamper}",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _decode(result: subprocess.CompletedProcess[bytes]) -> list[object]:
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stderr == b""
    decoded = eir_canonical_cbor_decode(result.stdout)
    assert isinstance(decoded, list)
    return decoded


def _assert_arrays_only(value: object) -> None:
    if isinstance(value, list):
        for item in value:
            _assert_arrays_only(item)
        return
    assert isinstance(value, (bytes, int, str))


def _global_rows(raw: list[object]) -> dict[str, list[object]]:
    rows = raw[3]
    assert isinstance(rows, list)
    result: dict[str, list[object]] = {}
    for row in rows:
        assert isinstance(row, list)
        key = row[0]
        assert isinstance(key, list)
        result[str(key[1])] = row
    return result


def _expected_targets() -> list[list[object]]:
    rows = json.loads(FROZEN_TARGETS.read_text(encoding="utf-8"))["details"][
        "compiler_derived_dispatch_proof"
    ]["targets"]
    return [[row["index"], row["name"], row["qual_type"]] for row in rows]


def _represented_domain1_subjects(raw: list[object]) -> set[tuple[object, ...]]:
    rows = raw[2]
    assert isinstance(rows, list)
    subjects: set[tuple[object, ...]] = set()
    for row in rows:
        assert isinstance(row, list) and len(row) == 4
        subject, _properties, disposition, _blockers = row
        assert isinstance(subject, list) and isinstance(disposition, int)
        if disposition == 1:
            subjects.add(_freeze(subject))
    return subjects


def _freeze(value: object) -> tuple[object, ...]:
    assert isinstance(value, list)
    return tuple(_freeze(item) if isinstance(item, list) else item for item in value)


def test_level2_transport_has_exact_descriptors_and_no_final_profile_or_root(
    docker_build: DockerBuild,
) -> None:
    raw = _decode(_run(docker_build))
    assert len(raw) == 5
    assert raw[0] == _expected_targets()
    assert len(raw[0]) == 116
    assert [row[0] for row in raw[0]] == list(range(116))
    assert isinstance(raw[1], list) and len(raw[1]) == 3
    _assert_arrays_only(raw)
    # This is intentionally internal transport: it begins with descriptors,
    # not the final artifact's protocol/profile/registry-root fields.
    assert not isinstance(raw[0][0][0], bytes)


def test_live_fd3_receipt_has_exact_eleven_event_wire_and_final_repetition(
    docker_build: DockerBuild,
) -> None:
    capture = _run_capture(docker_build)
    _decode(capture.result)
    assert capture.result.stderr == b""
    assert capture.receipt.startswith(b"V631CR01")
    assert not capture.result.stdout.startswith(b"V631CR01")
    assert len(capture.receipt) <= 16_777_216

    events = _decode_receipt_stream(capture.receipt)
    expected_codes = [1, 2, 3, 2, 2, 4, 2, 2, 2, 2, 5]
    assert len(events) == 11
    assert all(len(event) == 5 for event in events)
    assert [event[:4] for event in events] == [
        [631302, 1, sequence, code]
        for sequence, code in enumerate(expected_codes)
    ]

    binding = events[0][4]
    assert isinstance(binding, list) and len(binding) == 3
    assert binding[0] == 3
    assert isinstance(binding[1], int) and binding[1] >= 0
    assert isinstance(binding[2], int) and binding[2] > 0
    phase_sequences = (1, 3, 4, 6, 7, 8, 9)
    for phase, sequence in enumerate(phase_sequences):
        assert events[sequence][4] == [phase, phase]

    driver_argv = events[2][4]
    cc1_argv = events[5][4]
    assert isinstance(driver_argv, list) and driver_argv
    assert isinstance(cc1_argv, list) and cc1_argv
    assert str(driver_argv[0]).endswith("/clang-tool")
    assert driver_argv.count("--no-default-config") == 1
    assert cc1_argv[0] == "-cc1"
    assert cc1_argv.count("-cc1") == 1
    assert events[10][4] == [
        631302,
        1,
        binding,
        "fixture.cc",
        [],
        driver_argv,
        cc1_argv,
        [[phase, phase, sequence] for phase, sequence in enumerate(phase_sequences)],
    ]


def test_each_phase_frame_is_one_complete_fd3_write_syscall(
    docker_build: DockerBuild,
) -> None:
    capture = _run_capture(docker_build, trace_fd3_writes=True)
    _decode(capture.result)
    frame_spans = _receipt_frame_spans(capture.receipt)
    write_records = _decode_write_trace(capture.write_trace)

    write_spans: list[tuple[int, int, int, int]] = []
    cursor = 0
    for requested, result in write_records:
        write_spans.append((cursor, cursor + result, requested, result))
        cursor += result
    assert cursor == len(capture.receipt)

    phase_frames = [(start, end) for start, end, event in frame_spans if event[3] == 2]
    assert len(phase_frames) == 7
    for phase_start, phase_end in phase_frames:
        intersecting = [
            record
            for record in write_spans
            if record[0] < phase_end and record[1] > phase_start
        ]
        assert intersecting == [
            (phase_start, phase_end, phase_end - phase_start, phase_end - phase_start)
        ]


def test_peer_pipe_identity_and_receipt_eof_precede_process_teardown(
    docker_build: DockerBuild,
) -> None:
    capture, metadata = _run_peer_observed_capture(docker_build)
    _decode(capture.result)
    events = _decode_receipt_stream(capture.receipt)
    assert len(events) == 11 and all(len(event) == 5 for event in events)
    binding = events[0][4]
    assert isinstance(binding, list)
    assert binding == [
        3,
        metadata["read_st_dev"],
        metadata["read_st_ino"],
    ]
    assert metadata["alive_at_receipt_eof"] is True
    assert isinstance(metadata["pipe_size"], int)
    assert isinstance(metadata["stdout_length"], int)
    assert metadata["stdout_length"] > metadata["pipe_size"]


@pytest.mark.parametrize(
    "capture_context_hex",
    [
        VALID_CAPTURE_CONTEXT_HEX.upper(),
        VALID_CAPTURE_CONTEXT_HEX[:-1],
        VALID_CAPTURE_CONTEXT_HEX + "00",
        eir_canonical_cbor_encode([2, "fixture.cc", []]).hex(),
        eir_canonical_cbor_encode([1, "../fixture.cc", []]).hex(),
        (b"\x98\x03" + bytes.fromhex(VALID_CAPTURE_CONTEXT_HEX)[1:]).hex(),
        (bytes.fromhex(VALID_CAPTURE_CONTEXT_HEX)[:-1] + b"\xf5").hex(),
        (bytes.fromhex(VALID_CAPTURE_CONTEXT_HEX)[:-1] + b"\x81\x18\x00").hex(),
    ],
    ids=(
        "uppercase-hex",
        "odd-hex",
        "trailing-cbor",
        "wrong-version",
        "parent-path",
        "noncanonical-top-array",
        "boolean-profile",
        "noncanonical-nested-integer",
    ),
)
def test_capture_context_transport_rejects_noncanonical_or_wrong_values(
    docker_build: DockerBuild,
    capture_context_hex: str,
) -> None:
    capture = _run_capture(docker_build, capture_context_hex=capture_context_hex)
    assert capture.result.returncode == 66
    assert capture.result.stdout == b""
    assert capture.result.stderr == (
        b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"
    )
    assert capture.receipt == b""


def test_context_is_exactly_once_and_production_requires_real_fd3(
    docker_build: DockerBuild,
) -> None:
    duplicate = _run_capture(
        docker_build,
        collector_arguments=(
            f"--capture-context-v1-cbor-hex={VALID_CAPTURE_CONTEXT_HEX}",
        ),
    )
    assert duplicate.result.returncode == 66
    assert duplicate.receipt == b""

    missing = _run(docker_build, missing_fd3=True)
    assert missing.returncode == 66
    assert missing.stdout == b""
    assert missing.stderr == b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"

    regular = _run_capture(docker_build, regular_fd3=True)
    assert regular.result.returncode == 66
    assert regular.result.stdout == b""
    assert regular.result.stderr == (
        b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"
    )
    assert regular.receipt == b""

    production_test_bypass = _run(docker_build, no_fd3_receipt=True)
    assert production_test_bypass.returncode == 66
    assert production_test_bypass.stdout == b""
    assert production_test_bypass.stderr == (
        b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"
    )


def test_terminal_driver_failure_closes_fd3_after_the_emitted_prefix(
    docker_build: DockerBuild,
) -> None:
    capture = _run_capture(
        docker_build,
        compiler_arguments=("@/v631302/src/flags.rsp",),
    )
    assert capture.result.returncode == 66
    assert capture.result.stdout == b""
    assert capture.result.stderr == (
        b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"
    )
    events = _decode_receipt_stream(capture.receipt)
    assert [event[:4] for event in events] == [
        [631302, 1, 0, 1],
        [631302, 1, 1, 2],
    ]
    assert events[1][4] == [0, 0]


def test_receipt_calls_surround_the_single_driver_and_cc1_execution_calls() -> None:
    source = (
        ROOT
        / "evaluation_v6_3_1/native/m0_diagnostic_collector/M0DiagnosticCollector.cpp"
    ).read_text(encoding="ascii")
    assert source.count("driver.BuildCompilation(") == 1
    assert source.count("invocation.run()") == 1
    assert source.count("clang::tooling::FixedCompilationDatabase") == 1
    main_body = source.split("int main(int argc, char** argv)", 1)[1]
    assert main_body.count("expand_driver_once(*command") == 1
    receipt_start = main_body.index("receipt->start();")
    expand_call = main_body.index("expand_driver_once(*command")
    assert receipt_start < expand_call
    expansion_body = source.split("ExpandedInvocation expand_driver_once", 1)[1].split(
        "#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)", 1
    )[0]
    database = expansion_body.index("clang::tooling::FixedCompilationDatabase")
    first_adjuster = expansion_body.index("getClangStripOutputAdjuster()")
    assert database < first_adjuster
    driver_frozen = source.index("receipt->driver_argv_frozen(driver_argv);")
    driver_begin = source.index("receipt->driver_execution_begin();")
    build = source.index("driver.BuildCompilation(")
    cc1_extract = source.index("clang::tooling::getCC1Arguments(")
    cc1_frozen = source.index("receipt->cc1_argv_frozen(copied_cc1_argv);")
    cc1_begin = source.index("receipt->cc1_execution_begin();")
    run = source.index("invocation.run()")
    cc1_end = source.index("receipt->cc1_execution_end();")
    finalize = source.index("receipt->finalize();")
    stdout_write = source.index(
        "std::cout.write(reinterpret_cast<const char*>(output.data())"
    )
    assert driver_frozen < driver_begin < build < cc1_extract < cc1_frozen
    assert cc1_frozen < cc1_begin < run < cc1_end < finalize < stdout_write


def test_path_and_identity_serializers_have_no_pointer_or_candidate_preimage() -> None:
    source = (
        ROOT
        / "evaluation_v6_3_1/native/m0_diagnostic_collector/M0DiagnosticCollector.cpp"
    ).read_text(encoding="ascii")
    assert "candidate_id" not in source
    assert "uintptr" not in source
    assert "std::hash" not in source
    assert "unordered_map" not in source
    assert "unordered_set" not in source
    # The production transport write plus the structural-test-only argv audit.
    assert source.count("reinterpret_cast") == 2
    assert "reinterpret_cast<const char*>(output.data())" in source

    receipt_argument_guard = source.split(
        "void require_receipt_safe_argument(std::string_view argument)", 1
    )[1].split("void require_receipt_safe_arguments", 1)[0]
    assert "argument.empty()" not in receipt_argument_guard
    assert "argument.find('\\0')" in receipt_argument_guard
    assert 'argument.starts_with("@")' in receipt_argument_guard
    assert 'argument == "--config"' in receipt_argument_guard
    assert 'argument.starts_with("--config=")' in receipt_argument_guard
    assert 'argument.starts_with("--config-system-dir=")' in receipt_argument_guard
    assert 'argument.starts_with("--config-user-dir=")' in receipt_argument_guard


def test_level2_fresh_parses_and_independent_builds_are_byte_identical(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    first = _run(docker_build)
    second = _run(docker_build)
    independent = _build_collector(docker_build.docker, tmp_path / "independent-build")
    third = _run(independent)
    first_binary = docker_build.work / "build/bin/v631302-m0-diagnostic-collector"
    independent_binary = independent.work / "build/bin/v631302-m0-diagnostic-collector"
    assert first_binary.stat().st_size == independent_binary.stat().st_size
    assert hashlib.sha256(first_binary.read_bytes()).digest() == hashlib.sha256(
        independent_binary.read_bytes()
    ).digest()
    assert first.stdout == second.stdout == third.stdout
    _decode(first)


def test_test_only_driver_cc1_audit_exposes_one_direct_frontend_shape(
    docker_build: DockerBuild,
    docker_structural_build: DockerBuild,
) -> None:
    audit = _run(
        docker_structural_build,
        collector_arguments=("--test-driver-cc1-audit",),
        no_fd3_receipt=True,
    )
    assert audit.returncode == 0, audit.stderr.decode("utf-8", errors="replace")
    assert audit.stderr == b""
    decoded = eir_canonical_cbor_decode(audit.stdout)
    assert isinstance(decoded, list) and decoded[:2] == [631302, 4]
    driver_argv, cc1_argv = decoded[2:]
    assert isinstance(driver_argv, list) and isinstance(cc1_argv, list)
    assert str(driver_argv[0]).endswith("/clang-tool")
    assert driver_argv.count("-fsyntax-only") == 1
    assert not any(str(argument).startswith("-o") for argument in driver_argv)
    assert any(str(argument).startswith("-resource-dir=") for argument in driver_argv)
    assert driver_argv.count("--no-default-config") == 1
    assert cc1_argv[0] == "-cc1"
    assert cc1_argv.count("-cc1") == 1
    assert PRIMARY in cc1_argv
    assert "-fsyntax-only" in cc1_argv

    production = _run(
        docker_build,
        collector_arguments=("--test-driver-cc1-audit",),
    )
    assert production.returncode == 66
    assert production.stdout == b""
    assert production.stderr == b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"


def test_response_file_and_multi_frontend_shapes_fail_closed(
    docker_build: DockerBuild,
) -> None:
    response_file = _run(
        docker_build,
        compiler_arguments=("@/v631302/src/flags.rsp",),
    )
    assert response_file.returncode == 66
    assert response_file.stdout == b""
    assert response_file.stderr == b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"

    multi_frontend = _run(
        docker_build,
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "-I",
            "/v631302/src",
            "/v631302/src/friend_definition_fixture.cc",
        ),
    )
    assert multi_frontend.returncode == 66
    assert multi_frontend.stdout == b""
    assert multi_frontend.stderr == b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"


@pytest.mark.parametrize(
    "config_arguments",
    [
        ("--config=/v631302/src/driver.cfg",),
        ("--config", "/v631302/src/driver.cfg"),
        ("--config-system-dir=/v631302/src",),
        ("--config-user-dir=/v631302/src",),
    ],
)
def test_driver_config_expansion_controls_fail_closed(
    docker_build: DockerBuild,
    config_arguments: tuple[str, ...],
) -> None:
    result = _run(
        docker_build,
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "-I",
            "/v631302/src",
            *config_arguments,
        ),
    )
    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"


def test_domain3_embeds_exact_represented_domain1_instances_without_heuristics(
    docker_build: DockerBuild,
) -> None:
    raw = _decode(_run(docker_build))
    represented_subjects = _represented_domain1_subjects(raw)
    domain3_rows = raw[4]
    assert isinstance(domain3_rows, list)
    assert len(domain3_rows) == len(represented_subjects)
    encoded_instances = [eir_canonical_cbor_encode(row[0]) for row in domain3_rows]
    assert encoded_instances == sorted(encoded_instances)

    observed_subjects: set[tuple[object, ...]] = set()
    instances: set[tuple[object, ...]] = set()
    for row in domain3_rows:
        assert isinstance(row, list) and len(row) == 2
        instance, occurrences = row
        assert isinstance(instance, list) and len(instance) == 3
        assert instance[0] == 2
        subject, semantic_key = instance[1:]
        assert isinstance(subject, list) and isinstance(semantic_key, list)
        assert isinstance(occurrences, list)
        frozen_subject = _freeze(subject)
        frozen_instance = _freeze(instance)
        assert frozen_subject in represented_subjects
        assert frozen_subject not in observed_subjects
        assert frozen_instance not in instances
        observed_subjects.add(frozen_subject)
        instances.add(frozen_instance)

        # subject = [[2, path], kind, [path, begin, end]]
        # semantic = [kind, name, type, linkage, targets, path, begin, end]
        assert subject[0][0] == 2
        assert subject[1] == semantic_key[0]
        assert subject[2][0] == semantic_key[5]
        assert subject[2][1] == semantic_key[6]
        assert subject[2][2] == semantic_key[7]

    assert observed_subjects == represented_subjects

    linkage_by_name = {str(row[0][2][1]): row[0][2][3] for row in domain3_rows}
    assert linkage_by_name["internal_linkage_probe"] == 2
    assert linkage_by_name["probe"] == 1


def test_structural_paths_are_translation_unit_rooted_and_nontrivial(
    docker_build: DockerBuild,
) -> None:
    raw = _decode(_run(docker_build))
    source_rows = raw[2]
    global_rows = raw[3]
    invocation_rows = raw[4]
    assert isinstance(source_rows, list)
    assert isinstance(global_rows, list)
    assert isinstance(invocation_rows, list)
    absolute_paths = [row[0][0] for row in source_rows]
    absolute_paths.extend(row[0][8] for row in global_rows)
    assert all(path[0] == 2 for path in absolute_paths)
    indices = [path[1] for path in absolute_paths]
    assert all(all(isinstance(index, int) and index >= 0 for index in path) for path in indices)
    assert max(len(path) for path in indices) >= 2
    assert len({tuple(path) for path in indices}) >= len(source_rows)
    occurrence_paths = [occurrence[0][0] for row in invocation_rows for occurrence in row[1]]
    assert all(path and all(isinstance(index, int) and index >= 0 for index in path) for path in occurrence_paths)


def test_structural_contract_preserves_v1_paths_and_filters_duplicate_alias_edges(
    docker_structural_build: DockerBuild,
) -> None:
    first = _run(
        docker_structural_build,
        collector_arguments=(
            "--test-structural-audit",
            "--test-inject-repeated-rav-edge",
        ),
    )
    second = _run(
        docker_structural_build,
        collector_arguments=(
            "--test-structural-audit",
            "--test-inject-repeated-rav-edge",
        ),
    )
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    audit = _decode(first)
    assert len(audit) == 12
    assert audit[:3] == [631302, 2, [2, 16, 1, 1, 1, 0, 16, 1, 1]]
    assert 3 <= audit[3] <= 16
    assert audit[4] > 0
    assert audit[5] > 0
    assert audit[6] > 0  # direct RAV repeated a frozen core edge
    assert audit[7] > 0  # direct RAV repeated the same supplemental edge
    assert audit[8] > 0  # one AST object was reached through multiple paths

    v1_rows = audit[9]
    supplemental_rows = audit[10]
    assert isinstance(v1_rows, list) and len(v1_rows) == audit[4]
    assert isinstance(supplemental_rows, list) and len(supplemental_rows) == audit[5]
    for kind, original, projected, retained, span in v1_rows:
        assert isinstance(kind, str)
        assert original == projected
        assert retained == 1
        assert original[0] == 2
        assert all(isinstance(index, int) and index >= 0 for index in original[1])
        assert isinstance(span, list) and len(span) in (0, 3)
    for kind, projected, span in supplemental_rows:
        assert isinstance(kind, str)
        assert projected[0] == 2
        assert all(isinstance(index, int) and index >= 0 for index in projected[1])
        assert isinstance(span, list) and len(span) in (0, 3)

    core_edges, rav_edges = audit[11]
    assert core_edges and rav_edges
    assert all(len(row) == 7 for row in core_edges)
    assert all(len(row) == 10 for row in rav_edges)
    assert all(row[6] == int(row[3] == row[5]) for row in core_edges)

    core_duplicates = [row for row in rav_edges if row[6] == 1]
    repeated_raw = [row for row in rav_edges if row[5] == 0]
    assert core_duplicates and repeated_raw
    assert all(row[7] == [] and row[8] == [] and row[9] == 0 for row in core_duplicates)
    assert all(row[7] == [] and row[8] == [] and row[9] == 0 for row in repeated_raw)
    for repeated in repeated_raw:
        assert any(
            prior[1] == repeated[1]
            and prior[3] == repeated[3]
            and prior[4] < repeated[4]
            and prior[5] == 1
            for prior in rav_edges
        )

    proposed_by_final: dict[tuple[int, ...], set[tuple[int, ...]]] = {}
    for row in core_edges:
        proposed_by_final.setdefault(tuple(row[3][1]), set()).add(tuple(row[5][1]))
    for row in rav_edges:
        if row[8]:
            proposed_by_final.setdefault(tuple(row[3][1]), set()).add(tuple(row[8][0][1]))
    assert any(len(proposals) > 1 for proposals in proposed_by_final.values())

    encoded = eir_canonical_cbor_encode(audit)
    assert b"candidate_id" not in encoded
    assert b"pointer" not in encoded


def test_structural_stabilization_fails_closed_at_the_16_pass_bound(
    docker_structural_build: DockerBuild,
) -> None:
    result = _run(
        docker_structural_build,
        collector_arguments=("--test-force-nonconvergence",),
    )
    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"


def test_normal_collector_rejects_structural_test_switches(
    docker_build: DockerBuild,
) -> None:
    result = _run(
        docker_build,
        collector_arguments=("--test-structural-audit",),
    )
    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"
    observation = _run(
        docker_build,
        collector_arguments=("--test-definition-observation-audit",),
    )
    assert observation.returncode == 66
    assert observation.stdout == b""
    assert observation.stderr == b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"


def test_distinct_definition_nodes_in_one_redeclaration_family_are_not_collapsed(
    docker_build: DockerBuild,
    docker_structural_build: DockerBuild,
) -> None:
    primary = "/v631302/src/definition_redeclaration_error_fixture.cc"
    normal = _run(docker_build, primary=primary)
    assert normal.returncode == 65
    assert normal.stdout == b""
    assert normal.stderr.endswith(b"V631302_M0_ERROR:M0_FRONTEND_FAILED\n")

    first = _run(
        docker_structural_build,
        primary=primary,
        collector_arguments=("--test-definition-observation-audit",),
        no_fd3_receipt=True,
    )
    second = _run(
        docker_structural_build,
        primary=primary,
        collector_arguments=("--test-definition-observation-audit",),
        no_fd3_receipt=True,
    )
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr
    assert b"1 error generated" in first.stderr
    assert first.stdout == second.stdout
    audit = eir_canonical_cbor_decode(first.stdout)
    assert isinstance(audit, list)
    assert audit[:2] == [631302, 3]
    matching = [row for row in audit[2] if row[2] == "duplicate_definition"]
    assert len(matching) == 2
    assert all(row[1] == "FunctionDecl" and row[5] == 1 for row in matching)
    assert len({tuple(row[0][1]) for row in matching}) == 2
    assert len({row[8] for row in matching}) == 1


@pytest.mark.parametrize(
    ("fixture_name", "expected_kinds", "expected_edges"),
    [
        (
            "static_assert_template_fixture.cc",
            {"DeclStmt", "StaticAssertDecl", "StringLiteral", "CXXFunctionalCastExpr"},
            {
                ("DeclStmt", "StaticAssertDecl"),
                ("StaticAssertDecl", "CXXUnresolvedConstructExpr"),
                ("StaticAssertDecl", "StringLiteral"),
            },
        ),
        (
            "declarator_type_expression_fixture.cc",
            {"DeclStmt", "FieldDecl", "CallExpr"},
            {("CXXRecordDecl", "FieldDecl"), ("FieldDecl", "CallExpr")},
        ),
        (
            "explicit_template_argument_fixture.cc",
            {
                "StaticAssertDecl",
                "FunctionDecl",
                "CallExpr",
                "UnaryOperator",
                "SubstNonTypeTemplateParmExpr",
            },
            {
                ("DeclRefExpr", "ParenExpr"),
                ("ParenExpr", "CallExpr"),
                ("DeclRefExpr", "UnaryOperator"),
                ("ParmVarDecl", "ConstantExpr"),
                ("ConstantExpr", "SubstNonTypeTemplateParmExpr"),
            },
        ),
        (
            "friend_definition_fixture.cc",
            {"FriendDecl", "FunctionDecl"},
            {("FriendDecl", "FunctionDecl")},
        ),
    ],
)
def test_supplemental_clang_carriers_have_stable_pointer_free_paths(
    docker_structural_build: DockerBuild,
    fixture_name: str,
    expected_kinds: set[str],
    expected_edges: set[tuple[str, str]],
) -> None:
    arguments = (
        "-std=c++20",
        "-fsyntax-only",
        "-resource-dir=/opt/llvm-build/lib/clang/16",
        "-I",
        "/v631302/src",
    )
    first = _run(
        docker_structural_build,
        primary=f"/v631302/src/{fixture_name}",
        compiler_arguments=arguments,
        collector_arguments=("--test-structural-audit",),
    )
    second = _run(
        docker_structural_build,
        primary=f"/v631302/src/{fixture_name}",
        compiler_arguments=arguments,
        collector_arguments=("--test-structural-audit",),
    )
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    audit = _decode(first)
    rows = audit[9] + audit[10]
    source_rows = [row for row in rows if row[-1] and row[-1][0].endswith(fixture_name)]
    assert expected_kinds <= {row[0] for row in source_rows}

    paths = [
        tuple(row[2][1] if len(row) == 5 else row[1][1])
        for row in source_rows
    ]
    assert paths
    assert len(paths) == len(set(paths))
    core_edges, rav_edges = audit[11]
    observed_edges = {(row[0], row[2]) for row in core_edges + rav_edges}
    assert expected_edges <= observed_edges
    assert b"candidate_id" not in first.stdout
    assert b"pointer" not in first.stdout


def test_distinct_ast_objects_with_one_source_span_keep_distinct_v2_paths(
    docker_structural_build: DockerBuild,
) -> None:
    fixture_name = "same_span_identity_fixture.cc"
    first = _run(
        docker_structural_build,
        primary=f"/v631302/src/{fixture_name}",
        collector_arguments=("--test-structural-audit",),
    )
    second = _run(
        docker_structural_build,
        primary=f"/v631302/src/{fixture_name}",
        collector_arguments=("--test-structural-audit",),
    )
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    audit = _decode(first)

    expected_kinds = {
        "MaterializeTemporaryExpr",
        "ImplicitCastExpr",
        "CXXFunctionalCastExpr",
    }
    rows = [
        row
        for row in audit[9] + audit[10]
        if row[0] in expected_kinds
        and row[-1]
        and row[-1][0].endswith(fixture_name)
    ]
    by_span: dict[tuple[object, ...], list[list[object]]] = {}
    for row in rows:
        by_span.setdefault(tuple(row[-1]), []).append(row)
    witnesses = [
        group for group in by_span.values() if expected_kinds <= {row[0] for row in group}
    ]
    assert witnesses
    witness = witnesses[0]
    paths = [tuple((row[2] if len(row) == 5 else row[1])[1]) for row in witness]
    assert len(paths) == len(set(paths))


def test_domain2_collects_all_fixture_global_kinds_once_and_counts_rows(
    docker_build: DockerBuild,
) -> None:
    raw = _decode(_run(docker_build))
    rows = _global_rows(raw)
    assert rows["zero_global"][1] == 1
    assert rows["constant_global"][1] == 1
    assert rows["constinit_global"][1] == 1
    assert rows["dynamic_global"][1] == 2
    assert rows["destructed_global"][1] == 3
    assert rows["dynamic_destructed_global"][1] == 4
    assert rows["thread_global"][1] == 2
    assert rows["StaticMemberHolder::static_member"][1] == 1
    variable_template_rows = [
        row for row in raw[3] if str(row[0][1]).startswith("variable_template_value")
    ]
    assert len(variable_template_rows) == 1
    assert variable_template_rows[0][0][0] == "VarTemplateSpecializationDecl"
    assert rows["header_constant"][1] == 1
    assert rows["header_destructed"][1] == 3
    assert rows["header_empty"][1] == 1
    assert "extern_declaration_only" not in rows
    assert "local_static" not in rows
    domain2 = raw[1][1]
    assert domain2 == [len(rows), len(rows), 0, 0]
    assert all(row[2][0] in (0, 1) and row[3][0] in (0, 1) for row in rows.values())


def test_class_template_static_member_has_an_absolute_structural_path(
    docker_build: DockerBuild,
) -> None:
    first = _run(
        docker_build,
        primary="/v631302/src/class_template_static_fixture.cc",
    )
    second = _run(
        docker_build,
        primary="/v631302/src/class_template_static_fixture.cc",
    )
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    raw = eir_canonical_cbor_decode(first.stdout)
    matching = [
        row
        for row in raw[3]
        if "ClassTemplateStaticHolder" in str(row[0][1])
    ]
    assert matching
    assert all(row[0][0] == "VarDecl" for row in matching)
    assert all(row[0][8][0] == 2 and row[0][8][1] for row in matching)


def test_implicit_class_template_static_member_has_a_unique_structural_path(
    docker_build: DockerBuild,
) -> None:
    first = _run(
        docker_build,
        primary="/v631302/src/implicit_class_template_static_fixture.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-resource-dir=/opt/llvm-build/lib/clang/16",
            "-I",
            "/v631302/src",
        ),
    )
    second = _run(
        docker_build,
        primary="/v631302/src/implicit_class_template_static_fixture.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-resource-dir=/opt/llvm-build/lib/clang/16",
            "-I",
            "/v631302/src",
        ),
    )
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    raw = eir_canonical_cbor_decode(first.stdout)
    matching = [
        row
        for row in raw[3]
        if "integral_constant" in str(row[0][1]) and str(row[0][1]).endswith("::value")
    ]
    assert matching
    assert all(row[0][0] == "VarDecl" for row in matching)
    assert all(row[0][8][0] == 2 and row[0][8][1] for row in matching)
    paths = [tuple(row[0][8][1]) for row in raw[3]]
    assert len(paths) == len(set(paths))


def test_defaulted_friend_definition_has_a_unique_structural_path(
    docker_build: DockerBuild,
) -> None:
    first = _run(
        docker_build,
        primary="/v631302/src/friend_definition_fixture.cc",
    )
    second = _run(
        docker_build,
        primary="/v631302/src/friend_definition_fixture.cc",
    )
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == b""
    raw = _decode(first)
    matches = [
        row[0]
        for row in raw[4]
        if row[0][2][1] == "operator=="
    ]
    assert len(matches) == 1
    instance = matches[0]
    subject, semantic = instance[1:]
    assert subject[0][0] == 2 and subject[0][1]
    assert subject[1] == semantic[0] == "FunctionDecl"
    assert semantic[2] == "bool (const FriendHolder &, const FriendHolder &) noexcept"
    paths = [tuple(row[0][1][0][1]) for row in raw[4]]
    assert len(paths) == len(set(paths))


def test_static_assert_declaration_expression_has_a_structural_path(
    docker_build: DockerBuild,
) -> None:
    arguments = (
        "-std=c++20",
        "-fsyntax-only",
        "-resource-dir=/opt/llvm-build/lib/clang/16",
        "-I",
        "/v631302/src",
    )
    first = _run(
        docker_build,
        primary="/v631302/src/static_assert_template_fixture.cc",
        compiler_arguments=arguments,
    )
    second = _run(
        docker_build,
        primary="/v631302/src/static_assert_template_fixture.cc",
        compiler_arguments=arguments,
    )
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == b""
    raw = _decode(first)
    matching = [
        row
        for row in raw[4]
        if str(row[0][2][1]).startswith("static_assert_template")
    ]
    assert matching
    occurrences = [occurrence for row in matching for occurrence in row[1]]
    assert any(occurrence[0][1] == "CallExpr" for occurrence in occurrences)
    paths = [tuple(occurrence[0][0]) for occurrence in occurrences]
    assert all(paths)
    assert len(paths) == len(set(paths))


def test_declarator_typeloc_expression_has_a_structural_path(
    docker_build: DockerBuild,
) -> None:
    first = _run(
        docker_build,
        primary="/v631302/src/declarator_type_expression_fixture.cc",
    )
    second = _run(
        docker_build,
        primary="/v631302/src/declarator_type_expression_fixture.cc",
    )
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == b""
    raw = _decode(first)
    matching = [
        row
        for row in raw[4]
        if str(row[0][2][1]).startswith("declarator_type_expression")
    ]
    assert matching
    occurrences = [occurrence for row in matching for occurrence in row[1]]
    assert occurrences
    paths = [tuple(occurrence[0][0]) for occurrence in occurrences]
    assert all(paths)
    assert len(paths) == len(set(paths))


def test_explicit_template_argument_expression_has_a_structural_path(
    docker_build: DockerBuild,
) -> None:
    first = _run(
        docker_build,
        primary="/v631302/src/explicit_template_argument_fixture.cc",
    )
    second = _run(
        docker_build,
        primary="/v631302/src/explicit_template_argument_fixture.cc",
    )
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == b""
    raw = _decode(first)
    matching = [
        row
        for row in raw[4]
        if str(row[0][2][1]).startswith("explicit_template_argument")
    ]
    assert matching
    occurrences = [occurrence for row in matching for occurrence in row[1]]
    assert len(occurrences) >= 2
    paths = [tuple(occurrence[0][0]) for occurrence in occurrences]
    assert all(paths)
    assert len(paths) == len(set(paths))

    definitions = {
        str(row[0][2][1]): row[0][1][0]
        for row in raw[4]
        if str(row[0][2][1])
        in {
            "template_argument_declaration_target",
            "explicit_declaration_template_argument",
        }
    }
    assert set(definitions) == {
        "template_argument_declaration_target",
        "explicit_declaration_template_argument",
    }
    assert all(path[0] == 2 and path[1] for path in definitions.values())
    assert len({tuple(path[1]) for path in definitions.values()}) == 2


def test_identical_semantic_definitions_keep_distinct_v2_instance_keys(
    docker_build: DockerBuild,
) -> None:
    first = _run(
        docker_build,
        primary="/v631302/src/definition_instance_collision_fixture.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-resource-dir=/opt/llvm-build/lib/clang/16",
            "-I",
            "/v631302/src",
        ),
    )
    second = _run(
        docker_build,
        primary="/v631302/src/definition_instance_collision_fixture.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-resource-dir=/opt/llvm-build/lib/clang/16",
            "-I",
            "/v631302/src",
        ),
    )
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    raw = _decode(first)
    matching = [
        row[0]
        for row in raw[4]
        if row[0][2][1] == "std::__call_is_nt"
    ]
    assert len(matching) >= 2

    grouped: dict[bytes, list[list[object]]] = {}
    for instance in matching:
        grouped.setdefault(eir_canonical_cbor_encode(instance[2]), []).append(instance)
    collisions = [instances for instances in grouped.values() if len(instances) >= 2]
    assert collisions
    instances = collisions[0]
    encoded_instances = [eir_canonical_cbor_encode(instance) for instance in instances]
    assert len(encoded_instances) == len(set(encoded_instances))
    encoded_subjects = [eir_canonical_cbor_encode(instance[1]) for instance in instances]
    assert len(encoded_subjects) == len(set(encoded_subjects))
    assert all(instance[1][0][0] == 2 for instance in instances)

    source_by_subject = {
        eir_canonical_cbor_encode(row[0]): row for row in raw[2]
    }
    collision_rows = [
        source_by_subject[eir_canonical_cbor_encode(instance[1])]
        for instance in instances
    ]
    assert all(row[1][2] == 1 for row in collision_rows)
    assert all(row[1][4] == 1 for row in collision_rows)
    assert all(row[2] == 1 for row in collision_rows)
    assert len({eir_canonical_cbor_encode(row[0]) for row in collision_rows}) == len(
        collision_rows
    )
    semantic = instances[0][2]
    assert all(instance[2] == semantic for instance in instances)
    assert len({tuple(instance[1][0][1]) for instance in instances}) == len(instances)


def test_explicit_and_implicit_specializations_are_independent_and_redecls_are_exact(
    docker_build: DockerBuild,
    docker_structural_build: DockerBuild,
) -> None:
    primary = "/v631302/src/specialization_redeclaration_fixture.cc"
    first = _run(docker_build, primary=primary)
    second = _run(docker_build, primary=primary)
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    raw = _decode(first)

    source_by_subject = {
        eir_canonical_cbor_encode(row[0]): row for row in raw[2]
    }
    specialization_rows = [
        row for row in raw[4] if row[0][2][1] == "specialization_probe"
    ]
    assert len(specialization_rows) == 2
    assert {row[0][2][2] for row in specialization_rows} == {"int (int)", "int (double)"}
    source_rows = [
        source_by_subject[eir_canonical_cbor_encode(row[0][1])]
        for row in specialization_rows
    ]
    assert {(row[1][2], row[1][4]) for row in source_rows} == {(0, 1), (1, 1)}
    assert all(row[2] == 1 for row in source_rows)
    assert len({tuple(row[0][1][0][1]) for row in specialization_rows}) == 2

    names = [row[0][2][1] for row in raw[4]]
    assert "declaration_only" not in names
    assert names.count("redeclared_definition") == 1
    assert names.count("instantiate_specializations") == 1
    assert sum(row[2] == 3 and row[1][3] == 1 for row in raw[2]) == 1

    observation_result = _run(
        docker_structural_build,
        primary=primary,
        collector_arguments=("--test-definition-observation-audit",),
    )
    observation_audit = _decode(observation_result)
    assert observation_audit[:2] == [631302, 3]
    observed_specializations = [
        row for row in observation_audit[2] if row[2] == "specialization_probe" and row[7] == 1
    ]
    assert len(observed_specializations) == 2
    assert {(row[3], row[6]) for row in observed_specializations} == {
        ("int (int)", 0),
        ("int (double)", 1),
    }
    assert all(row[5] == 1 and row[9] >= 1 for row in observed_specializations)
    repeated_observations = [row for row in observed_specializations if row[9] >= 2]
    assert len(repeated_observations) == 1
    assert repeated_observations[0][3] == "int (int)"


def test_template_proof_is_empty_vaarg_is_unsupported_and_requires_is_absent(
    docker_build: DockerBuild,
) -> None:
    raw = _decode(_run(docker_build))
    source_rows = raw[2]
    assert isinstance(source_rows, list)
    properties = [row[1] for row in source_rows]
    assert all(len(row) == 6 and row[5] == [] for row in properties)
    assert any(row[3] == 1 for row in properties)  # pattern
    assert any(row[4] == 1 for row in properties)  # explicit/implicit concrete forms
    assert any(row[2] == 1 for row in properties)  # implicit instantiation
    assert all(row[2] != 2 for row in source_rows)

    occurrences = [occurrence for row in raw[4] for occurrence in row[1]]
    va_args = [row for row in occurrences if row[0][1] == "VAArgExpr"]
    assert len(va_args) == 1
    assert va_args[0][1] == 3
    assert va_args[0][2][0][1] == "M0_INVOCATION_INVENTORY_INCOMPLETE"
    assert all(row[0][1] != "RequiresExpr" for row in occurrences)
    domain3 = raw[1][2]
    assert domain3[0] == domain3[1] + domain3[3]
    assert domain3[3] == 1


def test_malformed_cli_and_frontend_failure_leave_stdout_empty(
    docker_build: DockerBuild,
) -> None:
    malformed = subprocess.run(
        [
            docker_build.docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "-e",
            "LD_LIBRARY_PATH=/opt/llvm-build/lib",
            "-v",
            f"{docker_build.work / 'build/bin'}:/v631302/bin:ro",
            IMAGE,
            COLLECTOR,
            "--protocol=631302",
            "--level=2",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert malformed.returncode == 66
    assert malformed.stdout == b""
    assert malformed.stderr == b"V631302_M0_ERROR:M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n"

    frontend = _run(
        docker_build,
        primary="/v631302/src/missing.cc",
        compiler_arguments=("-std=c++20", "-fsyntax-only", "-nostdinc"),
    )
    assert frontend.returncode == 65
    assert frontend.stdout == b""
    assert frontend.stderr.endswith(b"V631302_M0_ERROR:M0_FRONTEND_FAILED\n")


def test_strict_fresh_worker_fails_closed_under_amd64_emulation(
    docker_build: DockerBuild, tmp_path: Path
) -> None:
    clean = _build_fresh_worker(docker_build.docker, tmp_path / "clean")
    baseline = _run_fresh_worker(clean)
    contaminated = _run_fresh_worker(
        clean,
        {
            "PYTHONPATH": "/attacker",
            "PYTHONSTARTUP": "/attacker/startup.py",
            "PYTHONINSPECT": "1",
        },
    )
    assert baseline.returncode == contaminated.returncode == 66
    assert baseline.stdout == contaminated.stdout == b""
    assert baseline.stderr == contaminated.stderr == b""

    # Loader contamination does not turn the strict emulation failure into a
    # success or a diagnostic side channel.
    preloaded = _run_fresh_worker(clean, {"LD_PRELOAD": "/lib/x86_64-linux-gnu/libm.so.6"})
    assert preloaded.returncode == 66
    assert preloaded.stdout == b""
    assert preloaded.stderr == b""


def test_fresh_worker_substrate_rejects_extra_stdout_and_stderr(
    docker_build: DockerBuild, tmp_path: Path
) -> None:
    extra = _build_fresh_worker(
        docker_build.docker, tmp_path / "extra", "v631302_diagnostic_worker_extra_stdout.py"
    )
    stderr = _build_fresh_worker(
        docker_build.docker, tmp_path / "stderr", "v631302_diagnostic_worker_stderr.py"
    )
    assert _run_fresh_worker(extra).returncode == 66
    assert _run_fresh_worker(stderr).returncode == 66


def test_fresh_worker_substrate_uses_build_pinned_worker_bytes(
    docker_build: DockerBuild, tmp_path: Path
) -> None:
    fresh = _build_fresh_worker(docker_build.docker, tmp_path / "mutated")
    (fresh.work / "bootstrap.py").write_text("raise SystemExit(0)\n", encoding="ascii")
    result = _run_fresh_worker(fresh)
    assert result.returncode == 66
    assert result.stdout == b""


def test_strict_prelaunch_profile_fails_closed_under_amd64_emulation(
    docker_build: DockerBuild, tmp_path: Path
) -> None:
    fresh = _build_fresh_worker(
        docker_build.docker, tmp_path / "profile", "v631302_diagnostic_worker_profile_v1.py"
    )
    first = _run_prelaunch_profile(fresh)
    second = _run_prelaunch_profile(fresh)
    assert first.returncode == second.returncode == 66
    assert first.stdout == second.stdout == b""
    assert first.stderr == second.stderr == b""


@pytest.mark.parametrize(
    "tamper",
    ["collector-sha", "collector-build-id", "clang-sha", "clang-major", "worker-rewrite"],
)
def test_prelaunch_native_rejects_tampered_identity_or_worker_profile_without_repair(
    docker_build: DockerBuild, tmp_path: Path, tamper: str
) -> None:
    fresh = _build_fresh_worker(
        docker_build.docker, tmp_path / tamper, "v631302_diagnostic_worker_profile_v1.py"
    )
    result = _run_prelaunch_profile(fresh, tamper)
    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b""


@pytest.mark.parametrize("tamper", ["execution-profile", "bundle-root", "bundle-manifest"])
def test_prelaunch_native_rejects_tampered_profile_fields_without_substitution(
    docker_build: DockerBuild, tmp_path: Path, tamper: str
) -> None:
    fresh = _build_fresh_worker(
        docker_build.docker, tmp_path / tamper, "v631302_diagnostic_worker_profile_v1.py"
    )
    result = _run_prelaunch_profile(fresh, tamper)
    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b""


def test_prelaunch_profile_rejects_post_build_worker_byte_mutation(
    docker_build: DockerBuild, tmp_path: Path
) -> None:
    fresh = _build_fresh_worker(
        docker_build.docker, tmp_path / "profile-mutated", "v631302_diagnostic_worker_profile_v1.py"
    )
    (fresh.work / "bootstrap.py").write_text("raise SystemExit(0)\n", encoding="ascii")
    result = _run_prelaunch_profile(fresh)
    assert result.returncode == 66
    assert result.stdout == b""
