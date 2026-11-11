from __future__ import annotations

from hashlib import sha256
import importlib
import inspect
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from evaluation_v6_3_1.capture_v2_supervisor_transport import (
    AUTHORITY,
    CALIBRATION_UPLOAD_AUTHORITY,
    PRODUCTION_UPLOAD_AUTHORITY,
    UPLOAD_AUTHORITY,
    ZERO_AUTHORITY,
    SupervisorTransportError,
    _canonical_relative_path,
)


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


def _run(command: list[str], *, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True, timeout=timeout)


def _run_container(
    docker: str,
    arguments: list[str],
    *,
    cidfile: Path,
    timeout: int = 240,
) -> subprocess.CompletedProcess[str]:
    cidfile.unlink(missing_ok=True)
    try:
        return _run([docker, "run", "--cidfile", str(cidfile), *arguments], timeout=timeout)
    finally:
        if cidfile.exists():
            container_id = cidfile.read_text(encoding="ascii").strip()
            if container_id:
                subprocess.run(
                    [docker, "rm", "--force", container_id],
                    check=False,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
        cidfile.unlink(missing_ok=True)


@pytest.fixture(scope="module")
def static_supervisor(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped static supervisor tests")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-static-supervisor")
    binary = work / "v631302-native-supervisor"
    build_script = r"""
set -eu
mkdir -p /work/objects
includes='-I/src/evaluation_v6_3_1/native/capture_v2 -I/src/evaluation_v6_3_1/native/m0_diagnostic_collector'
for source in /src/evaluation_v6_3_1/native/capture_v2/*.cpp /src/evaluation_v6_3_1/native/m0_diagnostic_collector/RawCborWriter.cpp; do
    base=$(basename "$source" .cpp)
    case "$base" in
        Stage1*) continue ;;
    esac
    clang++-16 \
        -std=c++20 -fPIE \
        -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion \
        -Wno-sign-conversion -fexceptions \
        -isystem /opt/llvm-src/llvm/include \
        -isystem /opt/llvm-build/include \
        $includes \
        -c "$source" -o "/work/objects/$base.o"
done
g++ -static-pie /work/objects/*.o \
    -L/opt/llvm-build/lib \
    -lLLVMSupport -lz -ltinfo -ldl -lpthread -lm \
    -o /work/v631302-native-supervisor
"""
    result = _run_container(
        docker,
        [
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "-v",
            f"{ROOT}:/src:ro",
            "-v",
            f"{work}:/work:rw",
            IMAGE,
            "sh",
            "-lc",
            build_script,
        ],
        cidfile=work / "build.cid",
    )
    assert result.returncode == 0, result.stderr
    assert binary.is_file()
    return docker, work, binary


def test_transport_module_has_zero_authority_and_no_public_transport_override() -> None:
    module = importlib.import_module("evaluation_v6_3_1.capture_v2_supervisor_transport")
    assert ZERO_AUTHORITY is True
    assert AUTHORITY is False
    assert UPLOAD_AUTHORITY is False
    assert CALIBRATION_UPLOAD_AUTHORITY is False
    assert PRODUCTION_UPLOAD_AUTHORITY is False
    assert module.LAUNCH_GATE_V1_IMPLEMENTED is False
    assert "_open_and_stage_reviewed_supervisor" not in module.__all__
    assert "_stage_supervisor_from_open_fd" not in module.__all__
    assert not hasattr(module, "_execute_staged_supervisor_checkpoint3")

    source = inspect.getsource(module)
    assert "os.fork(" not in source
    assert "os.waitpid(" not in source
    assert "_SYS_EXECVEAT" not in source


@pytest.mark.parametrize(
    "value",
    ["", "/absolute", "trailing/", "a//b", "a/./b", "a/../b", "a\\b", "a\x00b"],
)
def test_supervisor_source_path_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(SupervisorTransportError):
        _canonical_relative_path(value)


def test_static_supervisor_has_no_interpreter_or_needed_objects(
    static_supervisor: tuple[str, Path, Path],
) -> None:
    docker, work, _ = static_supervisor
    result = _run_container(
        docker,
        [
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "-v",
            f"{work}:/work:ro",
            IMAGE,
            "sh",
            "-lc",
            "readelf -h /work/v631302-native-supervisor; "
            "readelf -l /work/v631302-native-supervisor; "
            "readelf -d /work/v631302-native-supervisor",
        ],
        cidfile=work / "readelf.cid",
    )
    assert result.returncode == 0, result.stderr
    assert "DYN (Position-Independent Executable file)" in result.stdout
    assert "INTERP" not in result.stdout
    assert "(NEEDED)" not in result.stdout


def test_static_supervisor_requires_exact_argv0_and_remains_fail_closed(
    static_supervisor: tuple[str, Path, Path],
) -> None:
    docker, work, _ = static_supervisor

    def invoke(argv_expression: str, name: str) -> subprocess.CompletedProcess[str]:
        code = (
            "import os; "
            f"os.execve('/work/v631302-native-supervisor', {argv_expression}, {{}})"
        )
        return _run_container(
            docker,
            [
                "--rm",
                "--network",
                "none",
                "--platform",
                "linux/amd64",
                "-v",
                f"{work}:/work:ro",
                IMAGE,
                "python3",
                "-c",
                code,
            ],
            cidfile=work / f"argv-{name}.cid",
        )

    exact = invoke("['v631302-native-supervisor']", "exact")
    wrong = invoke("['/work/v631302-native-supervisor']", "wrong")
    extra = invoke("['v631302-native-supervisor', 'unexpected']", "extra")
    assert exact.returncode == 65
    assert wrong.returncode == 64
    assert extra.returncode == 64
    assert exact.stdout == exact.stderr == ""
    assert wrong.stdout == wrong.stderr == ""
    assert extra.stdout == extra.stderr == ""


def test_copy_hash_and_required_seals_match_reviewed_binary(
    static_supervisor: tuple[str, Path, Path],
) -> None:
    docker, work, binary = static_supervisor
    expected = sha256(binary.read_bytes()).hexdigest()
    code = f"""
import fcntl
import json
import os
import signal
from evaluation_v6_3_1.capture_v2_supervisor_transport import (
    SupervisorTransportError,
    _open_and_stage_reviewed_supervisor,
    _stage_supervisor_from_open_fd,
)

root = os.open('/work', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    openat2_supported = True
    try:
        image = _open_and_stage_reviewed_supervisor(
            root,
            'v631302-native-supervisor',
            bytes.fromhex('{expected}'),
        )
    except SupervisorTransportError as exc:
        linuxkit = 'linuxkit' in open('/proc/version', encoding='ascii').read().lower()
        if 'errno=38' not in str(exc) or not linuxkit:
            raise
        openat2_supported = False
        source = os.open(
            '/work/v631302-native-supervisor',
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            image = _stage_supervisor_from_open_fd(
                source,
                bytes.fromhex('{expected}'),
            )
        finally:
            os.close(source)
    try:
        metadata = os.fstat(image.fileno())
        result = {{
            'digest': image.sha256_digest.hex(),
            'size': image.size,
            'mode': metadata.st_mode & 0o777,
            'cloexec': bool(fcntl.fcntl(image.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC),
            'required_seals': image.seals & 0x0f,
            'proc_link': os.readlink('/proc/self/fd/' + str(image.fileno())),
            'openat2_supported': openat2_supported,
        }}
    finally:
        image.close()
finally:
    os.close(root)

print(json.dumps(result, sort_keys=True))
"""
    result = _run_container(
        docker,
        [
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "-e",
            "PYTHONPATH=/src",
            "-v",
            f"{ROOT}:/src:ro",
            "-v",
            f"{work}:/work:ro",
            IMAGE,
            "python3",
            "-c",
            code,
        ],
        cidfile=work / "stage.cid",
    )
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed["digest"] == expected
    assert observed["size"] == binary.stat().st_size
    assert observed["mode"] == 0o500
    assert observed["cloexec"] is True
    assert observed["required_seals"] == 0x0F
    assert observed["proc_link"].startswith("/memfd:v631302-native-supervisor")
    assert type(observed["openat2_supported"]) is bool


def test_staging_rejects_wrong_digest(
    static_supervisor: tuple[str, Path, Path],
) -> None:
    docker, work, _ = static_supervisor
    code = """
import os
from evaluation_v6_3_1.capture_v2_supervisor_transport import (
    SupervisorTransportError,
    _stage_supervisor_from_open_fd,
)

source = os.open(
    '/work/v631302-native-supervisor',
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
)
try:
    try:
        _stage_supervisor_from_open_fd(source, b'\\x00' * 32)
    except SupervisorTransportError as exc:
        if 'digest chain does not match review' not in str(exc):
            raise
    else:
        raise SystemExit(91)
finally:
    os.close(source)
"""
    result = _run_container(
        docker,
        [
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "-e",
            "PYTHONPATH=/src",
            "-v",
            f"{ROOT}:/src:ro",
            "-v",
            f"{work}:/work:ro",
            IMAGE,
            "python3",
            "-c",
            code,
        ],
        cidfile=work / "negative-stage.cid",
    )
    assert result.returncode == 0, result.stderr


def test_openat2_rejects_symlink_source_on_capable_kernel(
    static_supervisor: tuple[str, Path, Path],
) -> None:
    docker, work, binary = static_supervisor
    alias = work / "supervisor-alias"
    alias.symlink_to("v631302-native-supervisor")
    expected = sha256(binary.read_bytes()).hexdigest()
    code = f"""
import os
from evaluation_v6_3_1.capture_v2_supervisor_transport import (
    SupervisorTransportError,
    _open_and_stage_reviewed_supervisor,
)

root = os.open('/work', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    try:
        image = _open_and_stage_reviewed_supervisor(
            root,
            'v631302-native-supervisor',
            bytes.fromhex('{expected}'),
        )
    except SupervisorTransportError as exc:
        linuxkit = 'linuxkit' in open('/proc/version', encoding='ascii').read().lower()
        if 'errno=38' in str(exc) and linuxkit:
            raise SystemExit(77)
        raise
    else:
        image.close()
    try:
        _open_and_stage_reviewed_supervisor(
            root,
            'supervisor-alias',
            bytes.fromhex('{expected}'),
        )
    except SupervisorTransportError:
        pass
    else:
        raise SystemExit(91)
finally:
    os.close(root)
"""
    result = _run_container(
        docker,
        [
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "-e",
            "PYTHONPATH=/src",
            "-v",
            f"{ROOT}:/src:ro",
            "-v",
            f"{work}:/work:ro",
            IMAGE,
            "python3",
            "-c",
            code,
        ],
        cidfile=work / "openat2.cid",
    )
    if result.returncode == 77:
        pytest.skip("Mac-hosted Docker kernel does not implement openat2")
    assert result.returncode == 0, result.stderr
