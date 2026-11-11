from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import shutil
import subprocess

import pytest

from evaluation_v6_3_1.eir_prebinding import (
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
)


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"
BUILD_ID = "V631302_RELAXED_FD_EMULATION_FIXTURE_V1"
WRAPPER_LABEL = (
    "B9_FIXTURE_TU_A4_RETIRED_CAPTURE_V1_EMULATED_RELAXED_FD_FUNCTIONAL_ONLY"
)
CURRENT_WORKER_SHA256 = "0dcbb36e1993a0b9192ed5178eefe5c3746efbe348ab6800a64cd4b8bdd6795a"
STALE_WORKER_SHA256 = "c10ff98ed1d72a6fab7fe1d4b4d9d3ae5d6bdc64249662088688365292ce095e"


@dataclass(frozen=True)
class RelaxedBuild:
    docker: str
    work: Path
    raw_capture_root: str
    harness: Path


def _run(command: list[str], *, check: bool = False) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check:
        assert result.returncode == 0, (
            f"command failed ({result.returncode}): {command!r}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
    return result


def _docker_prefix(docker: str, work: Path, *, repository: bool = True) -> list[str]:
    command = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
    ]
    if repository:
        command.extend(["-v", f"{ROOT}:/src:ro"])
    command.extend(["-v", f"{work}:/work:rw", "-w", "/work", IMAGE])
    return command


def _write_capture_inputs(work: Path) -> str:
    fixture = ROOT / "tests/fixtures/evaluation_v6_3_1/m0_diagnostic_collector"
    rows: list[list[object]] = []
    for name in ("fixture.cc", "m0_globals.h"):
        raw = (fixture / name).read_bytes()
        rows.append([f"/v631302/src/{name}", len(raw), hashlib.sha256(raw).digest()])
    (work / "driver.cbor").write_bytes(eir_canonical_cbor_encode([631302, 1, rows]))
    (work / "cc1.cbor").write_bytes(eir_canonical_cbor_encode([631302, 1, rows]))
    (work / "path.cbor").write_bytes(
        eir_canonical_cbor_encode(
            [631302, 1, "V631302_TEST_PATH_PROFILE_V1", "/v631302/src", "/work"]
        )
    )
    return hashlib.sha256(eir_canonical_cbor_encode(rows)).hexdigest()


def _configure_relaxed(
    docker: str,
    work: Path,
    *,
    build_name: str,
    raw: bytes,
    capture_root: str,
    bundle_root: str = "/work/bundle",
    source_root: str = "/src/evaluation_v6_3_1/native/m0_diagnostic_relaxed_fixture",
) -> Path:
    build = f"/work/{build_name}"
    result = _run(
        _docker_prefix(docker, work)
        + [
            "cmake",
            "-S",
            source_root,
            "-B",
            build,
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DV631302_RELAXED_BUNDLE_INIT_PATH={bundle_root}/evaluation_v6_3_1/__init__.py",
            f"-DV631302_RELAXED_BUNDLE_ENTRY_PATH={bundle_root}/evaluation_v6_3_1/m0_diagnostic_census.py",
            f"-DV631302_RELAXED_BUNDLE_PRIMITIVES_PATH={bundle_root}/evaluation_v6_3_1/m0_diagnostic_primitives.py",
            f"-DV631302_RELAXED_BUNDLE_WORKER_PATH={bundle_root}/worker/v631302_diagnostic_worker_v1.py",
            f"-DV631302_RELAXED_RAW_COLLECTOR_SIZE={len(raw)}",
            f"-DV631302_RELAXED_RAW_COLLECTOR_SHA256={hashlib.sha256(raw).hexdigest()}",
            f"-DV631302_RELAXED_RAW_COLLECTOR_CAPTURE_ROOT={capture_root}",
        ]
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    _run(
        _docker_prefix(docker, work)
        + [
            "cmake",
            "--build",
            build,
            "--target",
            "v631302-m0-diagnostic-relaxed-fd-fixture",
            "--",
            "-j2",
        ],
        check=True,
    )
    return work / build_name / "bin/v631302-m0-diagnostic-relaxed-fd-fixture"


def _build_boundary_harness(docker: str, work: Path) -> Path:
    _run(
        _docker_prefix(docker, work)
        + [
            "cmake",
            "-S",
            "/src/tests/native/v631302_relaxed_boundary_harness",
            "-B",
            "/work/harness",
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DV631302_RELAXED_GENERATED_INCLUDE=/work/relaxed/generated",
        ],
        check=True,
    )
    _run(
        _docker_prefix(docker, work)
        + [
            "cmake",
            "--build",
            "/work/harness",
            "--target",
            "v631302-relaxed-boundary-harness",
            "--",
            "-j2",
        ],
        check=True,
    )
    return work / "harness/bin/v631302-relaxed-boundary-harness"


def _run_harness(
    context: RelaxedBuild, *arguments: str, timeout: float = 20.0
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
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "-e",
            "LD_LIBRARY_PATH=/opt/llvm-build/lib",
            "-v",
            f"{context.work}:/work:rw",
            "-w",
            "/work",
            IMAGE,
            "/work/harness/bin/v631302-relaxed-boundary-harness",
            *arguments,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _worker(context: RelaxedBuild, name: str, source: str) -> str:
    path = context.work / name
    path.write_text(source, encoding="ascii")
    return f"/work/{name}"


def _run_relaxed(context: RelaxedBuild, *, binary: str = "/work/relaxed/bin/v631302-m0-diagnostic-relaxed-fd-fixture", raw: str = "/work/raw.cbor") -> subprocess.CompletedProcess[bytes]:
    return _run(
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
            f"{context.work}:/work:rw",
            "-w",
            "/work",
            IMAGE,
            binary,
            f"--raw-collector-cbor={raw}",
        ]
    )


@pytest.fixture(scope="module")
def relaxed_build(tmp_path_factory: pytest.TempPathFactory) -> RelaxedBuild:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != b"amd64":
        pytest.skip("the pinned linux/amd64 image is unavailable")
    work = tmp_path_factory.mktemp("v631302-relaxed-a7")

    bundle = work / "bundle"
    for relative in (
        "evaluation_v6_3_1/__init__.py",
        "evaluation_v6_3_1/m0_diagnostic_census.py",
        "evaluation_v6_3_1/m0_diagnostic_primitives.py",
        "worker/v631302_diagnostic_worker_v1.py",
    ):
        destination = bundle / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)

    _run(
        _docker_prefix(docker, work)
        + [
            "cmake",
            "-S",
            "/src/evaluation_v6_3_1/native/m0_diagnostic_collector",
            "-B",
            "/work/collector",
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DV631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS=ON",
        ],
        check=True,
    )
    _run(
        _docker_prefix(docker, work)
        + [
            "cmake",
            "--build",
            "/work/collector",
            "--target",
            "v631302-m0-diagnostic-collector",
            "--",
            "-j2",
        ],
        check=True,
    )

    source_root = _write_capture_inputs(work)
    fixture = ROOT / "tests/fixtures/evaluation_v6_3_1/m0_diagnostic_collector"
    capture = _run(
        [
            docker,
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
            "PYTHONPATH=/src",
            "-v",
            f"{ROOT}:/src:ro",
            "-v",
            f"{fixture}:/v631302/src:ro",
            "-v",
            f"{work}:/work:rw",
            "-w",
            "/work",
            IMAGE,
            "/usr/bin/python3.11",
            "/src/tools/capture_v631302_raw_collector.py",
            "--structural-test-no-fd3-receipt",
            "--collector",
            "/work/collector/bin/v631302-m0-diagnostic-collector",
            "--collector-build-id",
            "V631302_M0_DIAGNOSTIC_LEVEL2_TEST_V1",
            "--clang",
            "/opt/llvm-build/bin/clang-16",
            "--working-directory",
            "/work",
            "--primary-source",
            "/v631302/src/fixture.cc",
            "--source-root-sha256",
            source_root,
            "--runtime-root-sha256",
            hashlib.sha256(b"").hexdigest(),
            "--driver-input-manifest",
            "/work/driver.cbor",
            "--cc1-input-manifest",
            "/work/cc1.cbor",
            "--path-normalization-profile",
            "/work/path.cbor",
            "--compiler-argument=-std=c++20",
            "--compiler-argument=-fsyntax-only",
            "--compiler-argument=-nostdinc",
            "--compiler-argument=-I",
            "--compiler-argument=/v631302/src",
            "--environment=LD_LIBRARY_PATH=/opt/llvm-build/lib",
            "--output-raw",
            "/work/raw.cbor",
            "--output-capture",
            "/work/capture.cbor",
        ]
    )
    assert capture.returncode == 0, capture.stderr.decode("utf-8", errors="replace")
    capture_record = eir_canonical_cbor_decode((work / "capture.cbor").read_bytes())
    capture_root = hashlib.sha256(
        eir_canonical_cbor_encode([b"V631302_RAW_COLLECTOR_CAPTURE_V1", capture_record])
    ).hexdigest()
    raw = (work / "raw.cbor").read_bytes()
    _configure_relaxed(
        docker,
        work,
        build_name="relaxed",
        raw=raw,
        capture_root=capture_root,
    )
    harness = _build_boundary_harness(docker, work)
    return RelaxedBuild(
        docker=docker,
        work=work,
        raw_capture_root=capture_root,
        harness=harness,
    )


def test_amendment7_rebind_removes_stale_worker_identity() -> None:
    cmake = (
        ROOT / "evaluation_v6_3_1/native/m0_diagnostic_relaxed_fixture/CMakeLists.txt"
    ).read_text(encoding="ascii")
    assert CURRENT_WORKER_SHA256 in cmake
    assert STALE_WORKER_SHA256 not in cmake


def test_raw_collector_domain2_kind_matches_canonicalizer_contract(
    relaxed_build: RelaxedBuild,
) -> None:
    raw = eir_canonical_cbor_decode((relaxed_build.work / "raw.cbor").read_bytes())
    assert raw[3]
    kinds = {row[0][0] for row in raw[3]}
    assert kinds == {"VarDecl", "VarTemplateSpecializationDecl"}


def test_amendment8_fixture_label_does_not_claim_real_tu() -> None:
    source = (
        ROOT
        / "evaluation_v6_3_1/native/m0_diagnostic_relaxed_fixture/ExecutionOriginRelaxed.cpp"
    ).read_text(encoding="ascii")
    assert 'kWrapperLabel =\n    "B9_FIXTURE_TU_' in source
    assert 'kWrapperLabel =\n    "B9_REAL_TU_' not in source
    assert "std::chrono::milliseconds(300000)" in source
    assert "kMaximumCapturedRawCollectorBytes = 67108864ULL" in source


def test_two_fresh_relaxed_runs_reproduce_candidate_and_profile_chain(
    relaxed_build: RelaxedBuild,
) -> None:
    first = _run_relaxed(relaxed_build)
    second = _run_relaxed(relaxed_build)
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    first_wrapper = eir_canonical_cbor_decode(first.stdout)
    second_wrapper = eir_canonical_cbor_decode(second.stdout)
    assert first_wrapper[:3] == [631302, 1, WRAPPER_LABEL]
    assert second_wrapper[:3] == [631302, 1, WRAPPER_LABEL]
    assert first_wrapper[4] > 2 and second_wrapper[4] > 2
    assert first_wrapper[5] == second_wrapper[5]
    candidate = eir_canonical_cbor_decode(first_wrapper[5])
    second_candidate = eir_canonical_cbor_decode(second_wrapper[5])
    assert candidate == second_candidate
    assert len(candidate) == 9
    assert candidate[0:2] == [631302, 1]
    assert candidate[2][0] == first_wrapper[3]
    assert candidate[2][1] == BUILD_ID
    assert candidate[2][3:5] == [16, 1]
    assert len(candidate[2]) == 8
    assert len(candidate[3]) == 3
    assert len(candidate[4]) == 4
    assert all(isinstance(field, list) for field in candidate[5:9])
    first_roots = [
        hashlib.sha256(eir_canonical_cbor_encode(candidate[index])).digest()
        for index in range(5, 9)
    ]
    second_roots = [
        hashlib.sha256(eir_canonical_cbor_encode(second_candidate[index])).digest()
        for index in range(5, 9)
    ]
    assert first_roots == second_roots
    assert candidate[8] and second_candidate[8]
    assert eir_canonical_cbor_encode(candidate[8][0]) == eir_canonical_cbor_encode(
        second_candidate[8][0]
    )


def test_bound_raw_length_and_digest_fail_closed(relaxed_build: RelaxedBuild) -> None:
    raw = (relaxed_build.work / "raw.cbor").read_bytes()
    (relaxed_build.work / "raw-short.cbor").write_bytes(raw[:-1])
    changed = bytearray(raw)
    changed[-1] ^= 1
    (relaxed_build.work / "raw-changed.cbor").write_bytes(changed)
    for name in ("raw-short.cbor", "raw-changed.cbor"):
        result = _run_relaxed(relaxed_build, raw=f"/work/{name}")
        assert result.returncode == 66
        assert result.stdout == result.stderr == b""


def test_runtime_bundle_mutation_fails_after_successful_configuration(
    relaxed_build: RelaxedBuild,
) -> None:
    worker = relaxed_build.work / "bundle/worker/v631302_diagnostic_worker_v1.py"
    original = worker.read_bytes()
    try:
        worker.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        result = _run_relaxed(relaxed_build)
        assert result.returncode == 66
        assert result.stdout == result.stderr == b""
    finally:
        worker.write_bytes(original)


@pytest.mark.parametrize(
    "relative",
    [
        "evaluation_v6_3_1/__init__.py",
        "evaluation_v6_3_1/m0_diagnostic_census.py",
        "evaluation_v6_3_1/m0_diagnostic_primitives.py",
        "worker/v631302_diagnostic_worker_v1.py",
    ],
)
def test_bundle_symlink_substitution_fails_closed(
    relaxed_build: RelaxedBuild, relative: str
) -> None:
    member = relaxed_build.work / "bundle" / relative
    backup = member.with_name(f"{member.name}.symlink-test-copy")
    backup.write_bytes(member.read_bytes())
    member.unlink()
    member.symlink_to(backup.name)
    try:
        result = _run_relaxed(relaxed_build)
        assert result.returncode == 66
        assert result.stdout == result.stderr == b""
    finally:
        member.unlink()
        member.write_bytes(backup.read_bytes())


@pytest.mark.parametrize("raw", [b"\x18\x00", b"\x61\xff"])
def test_bound_malformed_or_invalid_utf8_raw_fails_native_validation(
    relaxed_build: RelaxedBuild, raw: bytes, tmp_path: Path
) -> None:
    name = f"malformed-{raw.hex()}"
    build_path = _configure_relaxed(
        relaxed_build.docker,
        relaxed_build.work,
        build_name=name,
        raw=raw,
        capture_root=hashlib.sha256(b"test-only:" + raw).hexdigest(),
    )
    raw_path = relaxed_build.work / f"{name}.cbor"
    raw_path.write_bytes(raw)
    result = _run_relaxed(
        relaxed_build,
        binary=f"/work/{build_path.relative_to(relaxed_build.work)}",
        raw=f"/work/{raw_path.name}",
    )
    assert result.returncode == 66
    assert result.stdout == result.stderr == b""


def test_stale_amendment9_worker_identity_fails_configuration(
    relaxed_build: RelaxedBuild,
) -> None:
    source = relaxed_build.work / "stale-worker-source"
    shutil.copytree(
        ROOT / "evaluation_v6_3_1/native/m0_diagnostic_relaxed_fixture", source
    )
    cmake = source / "CMakeLists.txt"
    text = cmake.read_text(encoding="ascii")
    text = text.replace("set(V631302_RELAXED_WORKER_SIZE 33817)",
                        "set(V631302_RELAXED_WORKER_SIZE 32685)")
    text = text.replace(CURRENT_WORKER_SHA256, STALE_WORKER_SHA256)
    cmake.write_text(text, encoding="ascii")
    raw = (relaxed_build.work / "raw.cbor").read_bytes()
    result = _run(
        _docker_prefix(relaxed_build.docker, relaxed_build.work)
        + [
            "cmake",
            "-S",
            "/work/stale-worker-source",
            "-B",
            "/work/stale-worker-build",
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DV631302_RELAXED_BUNDLE_INIT_PATH=/work/bundle/evaluation_v6_3_1/__init__.py",
            "-DV631302_RELAXED_BUNDLE_ENTRY_PATH=/work/bundle/evaluation_v6_3_1/m0_diagnostic_census.py",
            "-DV631302_RELAXED_BUNDLE_PRIMITIVES_PATH=/work/bundle/evaluation_v6_3_1/m0_diagnostic_primitives.py",
            "-DV631302_RELAXED_BUNDLE_WORKER_PATH=/work/bundle/worker/v631302_diagnostic_worker_v1.py",
            f"-DV631302_RELAXED_RAW_COLLECTOR_SIZE={len(raw)}",
            f"-DV631302_RELAXED_RAW_COLLECTOR_SHA256={hashlib.sha256(raw).hexdigest()}",
            f"-DV631302_RELAXED_RAW_COLLECTOR_CAPTURE_ROOT={relaxed_build.raw_capture_root}",
        ]
    )
    assert result.returncode != 0
    assert (
        b"WORKER does not match the exact zero-authority Amendment-9 working bundle"
        in result.stderr
    )


def test_stale_manifest_root_fails_at_runtime(relaxed_build: RelaxedBuild) -> None:
    source = relaxed_build.work / "stale-root-source"
    shutil.copytree(
        ROOT / "evaluation_v6_3_1/native/m0_diagnostic_relaxed_fixture", source
    )
    implementation = source / "ExecutionOriginRelaxed.cpp"
    text = implementation.read_text(encoding="ascii")
    current = "b5a5c7cefe1fc55db01a94516fc1a3068672a4f95d61f6a911b86d86d53fe6e6"
    stale = "0" + current[1:]
    assert stale != current and text.count(current) == 1
    implementation.write_text(text.replace(current, stale), encoding="ascii")
    raw = (relaxed_build.work / "raw.cbor").read_bytes()
    binary = _configure_relaxed(
        relaxed_build.docker,
        relaxed_build.work,
        build_name="stale-root-build",
        raw=raw,
        capture_root=relaxed_build.raw_capture_root,
        source_root="/work/stale-root-source",
    )
    result = _run_relaxed(
        relaxed_build,
        binary=f"/work/{binary.relative_to(relaxed_build.work)}",
    )
    assert result.returncode == 66
    assert result.stdout == result.stderr == b""


def test_raw_embedded_profile_cannot_override_prelaunch_profile(
    relaxed_build: RelaxedBuild,
) -> None:
    successful = _run_relaxed(relaxed_build)
    assert successful.returncode == 0
    wrapper = eir_canonical_cbor_decode(successful.stdout)
    candidate = eir_canonical_cbor_decode(wrapper[5])
    raw_value = eir_canonical_cbor_decode((relaxed_build.work / "raw.cbor").read_bytes())
    assert len(raw_value) == 5
    raw_value.append(candidate[2])
    injected = eir_canonical_cbor_encode(raw_value)
    binary = _configure_relaxed(
        relaxed_build.docker,
        relaxed_build.work,
        build_name="raw-profile-injection",
        raw=injected,
        capture_root=hashlib.sha256(b"raw-profile-injection").hexdigest(),
    )
    path = relaxed_build.work / "raw-profile-injection.cbor"
    path.write_bytes(injected)
    result = _run_relaxed(
        relaxed_build,
        binary=f"/work/{binary.relative_to(relaxed_build.work)}",
        raw=f"/work/{path.name}",
    )
    assert result.returncode == 66
    assert result.stdout == result.stderr == b""


def _valid_candidate_and_profile(context: RelaxedBuild) -> tuple[list[object], bytes, bytes]:
    successful = _run_relaxed(context)
    assert successful.returncode == 0
    wrapper = eir_canonical_cbor_decode(successful.stdout)
    candidate_bytes = wrapper[5]
    candidate = eir_canonical_cbor_decode(candidate_bytes)
    profile = eir_canonical_cbor_encode(candidate[2])
    return candidate, candidate_bytes, profile


def _candidate_harness(
    context: RelaxedBuild, name: str, candidate: bytes, profile: bytes
) -> subprocess.CompletedProcess[bytes]:
    candidate_path = context.work / f"{name}.candidate.cbor"
    profile_path = context.work / f"{name}.profile.cbor"
    candidate_path.write_bytes(candidate)
    profile_path.write_bytes(profile)
    return _run_harness(
        context,
        "candidate",
        f"/work/{candidate_path.name}",
        f"/work/{profile_path.name}",
    )


def test_native_candidate_harness_accepts_exact_worker_candidate(
    relaxed_build: RelaxedBuild,
) -> None:
    _, candidate, profile = _valid_candidate_and_profile(relaxed_build)
    result = _candidate_harness(relaxed_build, "candidate-valid", candidate, profile)
    assert result.returncode == 0
    assert result.stdout == result.stderr == b""


def test_malformed_candidate_shapes_fail_native_validation(
    relaxed_build: RelaxedBuild,
) -> None:
    candidate, _, profile = _valid_candidate_and_profile(relaxed_build)
    variants: dict[str, bytes] = {
        "eight-fields": eir_canonical_cbor_encode(candidate[:-1]),
        "non-array-source-census": eir_canonical_cbor_encode(
            candidate[:5] + [7] + candidate[6:]
        ),
    }
    for name, malformed in variants.items():
        result = _candidate_harness(relaxed_build, name, malformed, profile)
        assert result.returncode == 66
        assert result.stdout == result.stderr == b""


def test_noncanonical_and_malformed_utf8_candidates_fail_native_validation(
    relaxed_build: RelaxedBuild,
) -> None:
    candidate, candidate_bytes, profile = _valid_candidate_and_profile(relaxed_build)
    protocol = eir_canonical_cbor_encode(631302)
    marker = protocol + b"\x01"
    assert candidate_bytes.count(marker) == 1
    noncanonical = candidate_bytes.replace(marker, protocol + b"\x18\x01", 1)

    build_id = BUILD_ID.encode("ascii")
    assert candidate_bytes.count(build_id) == 1
    invalid_utf8 = candidate_bytes.replace(build_id, b"\xff" + build_id[1:], 1)

    for name, malformed in {
        "noncanonical-integer": noncanonical,
        "malformed-utf8": invalid_utf8,
    }.items():
        result = _candidate_harness(relaxed_build, name, malformed, profile)
        assert result.returncode == 66
        assert result.stdout == result.stderr == b""

    decoded_profile = candidate[2]
    pieces = [b"\x88"]
    for index, field in enumerate(decoded_profile):
        if index == 4:
            assert field == 1
            pieces.append(b"\x18\x01")
        else:
            pieces.append(eir_canonical_cbor_encode(field))
    decoded_equal_noncanonical_profile = b"".join(pieces)
    malformed_profile_candidate = b"\x89" + b"".join(
        [
            eir_canonical_cbor_encode(candidate[0]),
            eir_canonical_cbor_encode(candidate[1]),
            decoded_equal_noncanonical_profile,
            *(eir_canonical_cbor_encode(field) for field in candidate[3:]),
        ]
    )
    assert decoded_equal_noncanonical_profile != profile
    assert b"".join(
        [b"\x88", *(eir_canonical_cbor_encode(field) for field in decoded_profile)]
    ) == profile
    result = _candidate_harness(
        relaxed_build,
        "decoded-equal-noncanonical-profile",
        malformed_profile_candidate,
        profile,
    )
    assert result.returncode == 66
    assert result.stdout == result.stderr == b""


def test_output_frame_extra_bytes_and_over_cap_length_fail_before_payload(
    relaxed_build: RelaxedBuild,
) -> None:
    extra = b"V631DO01" + (0).to_bytes(8, "big") + b"x"
    oversized = b"V631DO01" + (1073741825).to_bytes(8, "big")
    for name, frame in {"extra": extra, "oversized": oversized}.items():
        path = relaxed_build.work / f"frame-{name}.bin"
        path.write_bytes(frame)
        result = _run_harness(relaxed_build, "frame", f"/work/{path.name}")
        assert result.returncode == 66
        assert result.stdout == result.stderr == b""


def test_concurrent_stdout_drain_prevents_stdin_deadlock(
    relaxed_build: RelaxedBuild,
) -> None:
    worker = _worker(
        relaxed_build,
        "worker-stdout-pressure.py",
        "import sys\n"
        "sys.stdout.buffer.write(b'X' * (1024 * 1024))\n"
        "sys.stdout.buffer.flush()\n"
        "while sys.stdin.buffer.read(65536):\n"
        "    pass\n",
    )
    result = _run_harness(relaxed_build, "process", worker, str(2 * 1024 * 1024))
    assert result.returncode == 0
    assert b"stdout_length=1048576\n" in result.stdout
    assert result.stderr == b""


@pytest.mark.parametrize(
    "name,source",
    [
        (
            "stderr-byte",
            "import sys\nsys.stderr.buffer.write(b'E')\nsys.stderr.buffer.flush()\n",
        ),
        (
            "stderr-pressure",
            "import sys\nsys.stderr.buffer.write(b'E' * (1024 * 1024))\n"
            "sys.stderr.buffer.flush()\n",
        ),
    ],
)
def test_any_stderr_fails_and_reaps_without_deadlock(
    relaxed_build: RelaxedBuild, name: str, source: str
) -> None:
    worker = _worker(relaxed_build, f"worker-{name}.py", source)
    result = _run_harness(relaxed_build, "process", worker, "0")
    assert result.returncode == 66
    assert result.stdout == result.stderr == b""


def test_extra_stdout_after_worker_frame_fails(relaxed_build: RelaxedBuild) -> None:
    worker = _worker(
        relaxed_build,
        "worker-extra-stdout.py",
        "import sys\n"
        "while sys.stdin.buffer.read(65536):\n"
        "    pass\n"
        "sys.stdout.buffer.write(b'V631DO01' + (0).to_bytes(8, 'big') + b'X')\n"
        "sys.stdout.buffer.flush()\n",
    )
    result = _run_harness(relaxed_build, "process-frame", worker, "131072")
    assert result.returncode == 66
    assert result.stderr == b""


def test_one_second_monotonic_timeout_kills_and_reaps_worker(
    relaxed_build: RelaxedBuild,
) -> None:
    worker = _worker(
        relaxed_build,
        "worker-timeout.py",
        "import signal\n"
        "import time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "while True:\n"
        "    time.sleep(1)\n",
    )
    result = _run_harness(relaxed_build, "timeout", worker, timeout=8.0)
    assert result.returncode == 66
    assert result.stderr == b""
    transcript = result.stdout.decode("ascii").splitlines()
    assert "deadline_clock=steady" in transcript
    assert "signal=9" in transcript
    assert "reaped=1" in transcript
    assert "wrapper_emitted=0" in transcript
    elapsed = int(next(row.split("=", 1)[1] for row in transcript if row.startswith("elapsed_ms=")))
    assert 1000 <= elapsed <= 5000


def test_replacing_worker_path_after_read_cannot_change_retained_bytes(
    relaxed_build: RelaxedBuild,
) -> None:
    original = _worker(
        relaxed_build,
        "worker-retained-original.py",
        "import sys\nsys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(b'ORIGINAL')\nsys.stdout.buffer.flush()\n",
    )
    replacement = _worker(
        relaxed_build,
        "worker-retained-replacement.py",
        "import sys\nsys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(b'REPLACED')\nsys.stdout.buffer.flush()\n",
    )
    result = _run_harness(
        relaxed_build, "retained-worker", original, replacement
    )
    assert result.returncode == 0
    assert result.stdout == b"ORIGINAL"
    assert result.stderr == b""


def test_only_relaxed_source_clears_interpreter_cloexec() -> None:
    strict = (
        ROOT / "evaluation_v6_3_1/native/m0_diagnostic_collector/ExecutionOrigin.cpp"
    ).read_text(encoding="ascii")
    relaxed = (
        ROOT
        / "evaluation_v6_3_1/native/m0_diagnostic_relaxed_fixture/ExecutionOriginRelaxed.cpp"
    ).read_text(encoding="ascii")
    bootstrap = "descriptor_flags & ~FD_CLOEXEC"
    assert bootstrap not in strict
    assert relaxed.count(bootstrap) == 1
    assert "V631302_RELAXED_IO_POLICY" not in strict
    assert "V631302_RELAXED_FD_EMULATION_FIXTURE_V1" not in strict
