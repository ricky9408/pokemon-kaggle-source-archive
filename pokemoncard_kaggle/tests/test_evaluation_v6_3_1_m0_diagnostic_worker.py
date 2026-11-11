from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "worker" / "v631302_diagnostic_worker_v1.py"
ENTRY_PATH = "evaluation_v6_3_1/m0_diagnostic_census.py"
WORKER_PATH = "worker/v631302_diagnostic_worker_v1.py"
FUTURE_PREFIX = b"from __future__ import annotations\n"


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 0xFF:
        return bytes(((major << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")


def _cbor(value: object) -> bytes:
    if type(value) is int:
        return _head(0, value)
    if type(value) is bytes:
        return _head(2, len(value)) + value
    if type(value) is str:
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if type(value) is list:
        return _head(4, len(value)) + b"".join(_cbor(item) for item in value)
    raise TypeError(type(value))


def _entry_source(body: str = "return A([631302,1,0,x])") -> bytes:
    return (
        FUTURE_PREFIX.decode("ascii")
        + "def canonicalize_diagnostic_census_v1(x):\n"
        " def H(m,n):\n"
        "  if n<24:return bytes([(m<<5)|n])\n"
        "  if n<256:return bytes([(m<<5)|24,n])\n"
        "  if n<65536:return bytes([(m<<5)|25])+n.to_bytes(2,'big')\n"
        "  if n<4294967296:return bytes([(m<<5)|26])+n.to_bytes(4,'big')\n"
        "  return bytes([(m<<5)|27])+n.to_bytes(8,'big')\n"
        " def A(v):\n"
        "  if type(v) is int:return H(0,v)\n"
        "  if type(v) is bytes:return H(2,len(v))+v\n"
        "  if type(v) is str:\n"
        "   q=v.encode('utf-8');return H(3,len(q))+q\n"
        "  return H(4,len(v))+b''.join([A(z) for z in v])\n"
        f" {body}\n"
    ).encode("ascii")


def _bundle(entry_source: bytes, *, worker_source: bytes | None = None, extra: list[tuple[str, bytes]] | None = None) -> tuple[list[object], dict[str, bytes]]:
    files = {
        "evaluation_v6_3_1/__init__.py": b"\n",
        ENTRY_PATH: entry_source,
        WORKER_PATH: WORKER.read_bytes() if worker_source is None else worker_source,
    }
    for path, source in extra or []:
        files[path] = source
    ordered = sorted(files.items(), key=lambda pair: pair[0].encode("utf-8"))
    manifest = [
        1,
        ENTRY_PATH,
        [[path, len(source), hashlib.sha256(source).digest()] for path, source in ordered],
    ]
    return manifest, dict(ordered)


def _profile(manifest: list[object], files: dict[str, bytes]) -> tuple[list[object], bytes]:
    if not Path("/proc/self/exe").exists():
        pytest.skip("the frozen worker interpreter pin requires Linux /proc/self/exe")
    executable = Path("/proc/self/exe").read_bytes()
    root = hashlib.sha256(
        _cbor([b"V631302_CANONICALIZER_BUNDLE_V1", 631302, 1, 1, manifest])
    ).digest()
    execution_profile = [
        1,
        [
            1,
            1,
            sys.hexversion,
            sys.implementation.cache_tag,
            sys.abiflags,
            len(executable),
            hashlib.sha256(executable).digest(),
        ],
        WORKER_PATH,
        hashlib.sha256(files[WORKER_PATH]).digest(),
        1,
        1,
        1,
        1,
    ]
    return [b"a" * 32, "collector", b"b" * 32, 16, 1, execution_profile, root, manifest], root


def _artifact(profile: list[object], root: bytes, manifest: list[object]) -> bytes:
    assert profile[6] == root and profile[7] == manifest
    return _cbor([631302, 1, profile, [], [], [], [], [], []])


def _input(entry_source: bytes, *, worker_source: bytes | None = None, extra: list[tuple[str, bytes]] | None = None, raw: bytes | None = None) -> bytes:
    manifest, files = _bundle(entry_source, worker_source=worker_source, extra=extra)
    profile, root = _profile(manifest, files)
    artifact = _artifact(profile, root, manifest) if raw is None else raw
    rows = [[row[0], files[row[0]]] for row in manifest[2]]
    payload = _cbor([631302, 1, profile, rows, artifact])
    return b"V631DI01" + len(payload).to_bytes(8, "big") + payload


def _run(payload: bytes, *, source: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    code = WORKER.read_bytes() if source is None else source
    return subprocess.run(
        [
            sys.executable,
            "-I", "-S", "-E", "-s", "-P", "-B", "-u", "-X", "utf8",
            "-c", code.decode("ascii"), "V631302_DIAGNOSTIC_WORKER_V1", WORKER_PATH,
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env={},
        check=False,
    )


def _success(result: subprocess.CompletedProcess[bytes]) -> bytes:
    assert result.returncode == 0
    assert result.stderr == b""
    assert result.stdout[:8] == b"V631DO01"
    size = int.from_bytes(result.stdout[8:16], "big")
    assert len(result.stdout) == 16 + size
    return result.stdout[16:]


def test_worker_source_is_ascii_single_import_and_size_bounded() -> None:
    source = WORKER.read_bytes()
    assert len(source) <= 65535
    assert source.endswith(b"\n")
    assert b"\r" not in source and b"\0" not in source
    assert all(byte < 128 for byte in source)
    assert source.count(b"import sys") == 1


def test_verified_synthetic_bundle_emits_exact_artifact() -> None:
    payload = _input(_entry_source("_ = V631302_BOUND_COLLECTOR_PROFILE_CBOR; return A([631302,1,0,x])"))
    first = _run(payload)
    second = _run(payload)
    assert _success(first) == _success(second)


def test_single_frame_requires_eof_and_fails_silently() -> None:
    result = _run(_input(_entry_source()) + b"x")
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


@pytest.mark.parametrize(
    "source",
    [
        b"import ast\n" + _entry_source(),
        b"import collections\n" + _entry_source(),
        b"import hashlib\n" + _entry_source(),
        b"import pathlib\n" + _entry_source(),
        b"import typing\n" + _entry_source(),
        b"import unicodedata\n" + _entry_source(),
    ],
)
def test_project_stdlib_imports_fail_closed(source: bytes) -> None:
    result = _run(_input(source))
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


def test_future_annotations_intrinsic_is_exact_entry_only_and_one_shot() -> None:
    _success(_run(_input(_entry_source())))
    invalid = (
        b"import __future__\n" + _entry_source()[len(FUTURE_PREFIX):],
        b"from __future__ import division\n" + _entry_source()[len(FUTURE_PREFIX):],
        b"from __future__ import annotations, generator_stop\n"
        + _entry_source()[len(FUTURE_PREFIX):],
        b"from __future__ import annotations as future_annotations\n"
        + _entry_source()[len(FUTURE_PREFIX):],
        FUTURE_PREFIX + FUTURE_PREFIX + _entry_source()[len(FUTURE_PREFIX):],
        b'"""leading module text"""\n' + _entry_source(),
        _entry_source()[len(FUTURE_PREFIX):],
    )
    for source in invalid:
        result = _run(_input(source))
        assert result.returncode == 80
        assert result.stdout == b"" and result.stderr == b""


def test_future_annotations_intrinsic_ignores_preloaded_real_module() -> None:
    original = WORKER.read_bytes()
    injected = (
        b"import sys\nsys.modules['__future__'] = object()\n"
        + original[len(b"import sys\n"):]
    )
    _success(_run(_input(_entry_source(), worker_source=injected), source=injected))


def test_future_annotations_intrinsic_is_rejected_in_dependency_module() -> None:
    helper = FUTURE_PREFIX + b"def marker():\n return 1\n"
    entry = (
        FUTURE_PREFIX
        + b"from .helper import marker\n"
        + _entry_source("marker(); return A([631302,1,0,x])")[len(FUTURE_PREFIX):]
    )
    result = _run(_input(entry, extra=[("evaluation_v6_3_1/helper.py", helper)]))
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


def test_private_project_replacement_loads_without_real_sys_modules() -> None:
    helper = b"def marker():\n return 1\n"
    entry = (
        FUTURE_PREFIX
        + b"from .helper import marker\n"
        + _entry_source("marker(); return A([631302,1,0,x])")[len(FUTURE_PREFIX):]
    )
    result = _run(_input(entry, extra=[("evaluation_v6_3_1/helper.py", helper)]))
    _success(result)


@pytest.mark.parametrize(
    "body",
    [
        "return b'\\x9f'",
        "return A([631302,1,1,b'x'])",
        "return A([631302,1,2,b'x'])",
        "raise SystemExit()",
        "print('leak'); return A([631302,1,0,x])",
        "import sys; return sys.modules",
        "return open('x')",
    ],
)
def test_entry_abi_and_restricted_facades_fail_closed(body: str) -> None:
    result = _run(_input(_entry_source(body)))
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


def test_imported_entry_callable_is_rejected() -> None:
    helper = b"def canonicalize_diagnostic_census_v1(x):\n return x\n"
    entry = b"from .helper import canonicalize_diagnostic_census_v1\n"
    result = _run(_input(entry, extra=[("evaluation_v6_3_1/helper.py", helper)]))
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


def test_preloaded_project_name_is_rejected_before_private_loading() -> None:
    original = WORKER.read_bytes()
    injected = b"import sys\nsys.modules['evaluation_v6_3_1.m0_diagnostic_census']=None\n" + original[len(b"import sys\n"):]
    result = _run(_input(_entry_source(), worker_source=injected), source=injected)
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


def test_worker_byte_hash_and_artifact_binding_mismatch_fail_closed() -> None:
    manifest, files = _bundle(_entry_source())
    profile, root = _profile(manifest, files)
    bad_profile = list(profile)
    bad_execution = list(profile[5])
    bad_execution[3] = b"z" * 32
    bad_profile[5] = bad_execution
    rows = [[row[0], files[row[0]]] for row in manifest[2]]
    payload = _cbor([631302, 1, bad_profile, rows, _artifact(profile, root, manifest)])
    result = _run(b"V631DI01" + len(payload).to_bytes(8, "big") + payload)
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


@pytest.mark.parametrize("field", [5, 6])
def test_preexecution_profile_execution_and_root_mismatches_fail_closed(field: int) -> None:
    manifest, files = _bundle(_entry_source())
    profile, root = _profile(manifest, files)
    bad_profile = list(profile)
    if field == 5:
        changed = list(profile[5])
        changed[4] = 0
        bad_profile[5] = changed
    else:
        bad_profile[6] = b"z" * 32
    rows = [[row[0], files[row[0]]] for row in manifest[2]]
    payload = _cbor([631302, 1, bad_profile, rows, _artifact(profile, root, manifest)])
    result = _run(b"V631DI01" + len(payload).to_bytes(8, "big") + payload)
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


def test_returned_profile_requires_exact_bound_cbor_without_worker_repair() -> None:
    manifest, files = _bundle(_entry_source())
    profile, root = _profile(manifest, files)
    returned_profile = list(profile)
    returned_profile[1] = "different-build"
    rows = [[row[0], files[row[0]]] for row in manifest[2]]
    payload = _cbor([631302, 1, profile, rows, _artifact(returned_profile, root, manifest)])
    result = _run(b"V631DI01" + len(payload).to_bytes(8, "big") + payload)
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


def test_old_shape_and_duplicate_profile_representations_fail_closed() -> None:
    manifest, files = _bundle(_entry_source())
    profile, root = _profile(manifest, files)
    rows = [[row[0], files[row[0]]] for row in manifest[2]]
    old_payload = _cbor([631302, 1, profile[5], root, manifest, rows, _artifact(profile, root, manifest)])
    result = _run(b"V631DI01" + len(old_payload).to_bytes(8, "big") + old_payload)
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


@pytest.mark.parametrize(
    "prefix",
    [
        b"V631302_BOUND_COLLECTOR_PROFILE_CBOR=bytes(bytearray(V631302_BOUND_COLLECTOR_PROFILE_CBOR))\n",
        b"del V631302_BOUND_COLLECTOR_PROFILE_CBOR\n",
    ],
)
def test_entry_body_reserved_profile_mutation_fails_closed(prefix: bytes) -> None:
    result = _run(_input(prefix + _entry_source()))
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


@pytest.mark.parametrize(
    "body",
    [
        "global V631302_BOUND_COLLECTOR_PROFILE_CBOR; V631302_BOUND_COLLECTOR_PROFILE_CBOR=bytes(bytearray(V631302_BOUND_COLLECTOR_PROFILE_CBOR)); return A([631302,1,0,x])",
        "global V631302_BOUND_COLLECTOR_PROFILE_CBOR; del V631302_BOUND_COLLECTOR_PROFILE_CBOR; return A([631302,1,0,x])",
    ],
)
def test_entry_invocation_reserved_profile_mutation_fails_closed(body: str) -> None:
    result = _run(_input(_entry_source(body)))
    assert result.returncode == 80
    assert result.stdout == b"" and result.stderr == b""


def test_template_result_requires_profile_integrity_first() -> None:
    good = _run(_input(_entry_source("return A([631302,1,2,b''])")))
    assert good.returncode == 81
    assert good.stdout == b"" and good.stderr == b""
    bad = _run(
        _input(
            _entry_source(
                "global V631302_BOUND_COLLECTOR_PROFILE_CBOR; V631302_BOUND_COLLECTOR_PROFILE_CBOR=bytes(bytearray(V631302_BOUND_COLLECTOR_PROFILE_CBOR)); return A([631302,1,2,b''])"
            )
        )
    )
    assert bad.returncode == 80
    assert bad.stdout == b"" and bad.stderr == b""


def test_prelaunch_profile_changes_preserve_bundle_root_but_change_output_profile() -> None:
    entry = _entry_source()
    manifest, files = _bundle(entry)
    profile_one, root = _profile(manifest, files)
    profile_two = list(profile_one)
    profile_two[0] = b"c" * 32
    profile_two[1] = "collector-two"
    profile_two[2] = b"d" * 32
    profile_two[3] = 17
    raw_one = _artifact(profile_one, root, manifest)
    raw_two = _artifact(profile_two, root, manifest)
    rows = [[row[0], files[row[0]]] for row in manifest[2]]
    first = _run(b"V631DI01" + len(_cbor([631302, 1, profile_one, rows, raw_one])).to_bytes(8, "big") + _cbor([631302, 1, profile_one, rows, raw_one]))
    second = _run(b"V631DI01" + len(_cbor([631302, 1, profile_two, rows, raw_two])).to_bytes(8, "big") + _cbor([631302, 1, profile_two, rows, raw_two]))
    assert _success(first) != _success(second)
