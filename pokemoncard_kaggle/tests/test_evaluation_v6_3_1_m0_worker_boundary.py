"""Adversarial tests for Sol Amendment 5 worker-boundary conformance.

These tests deliberately assert the Amendment 5 fail-closed contract.  They
are expected to expose gaps in a worker that executes the current vulnerable
same-interpreter implementation; they must not be weakened to make that
implementation green.
"""

from __future__ import annotations

import dis
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
RESERVED = "V631302_BOUND_COLLECTOR_PROFILE_CBOR"


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


_CANONICALIZER_PREFIX = (
    FUTURE_PREFIX
    + b"def canonicalize_diagnostic_census_v1(x):\n"
    + b" def H(m,n):\n"
    + b"  if n<24:return bytes([(m<<5)|n])\n"
    + b"  if n<256:return bytes([(m<<5)|24,n])\n"
    + b"  if n<65536:return bytes([(m<<5)|25])+n.to_bytes(2,'big')\n"
    + b"  if n<4294967296:return bytes([(m<<5)|26])+n.to_bytes(4,'big')\n"
    + b"  return bytes([(m<<5)|27])+n.to_bytes(8,'big')\n"
    + b" def A(v):\n"
    + b"  if type(v) is int:return H(0,v)\n"
    + b"  if type(v) is bytes:return H(2,len(v))+v\n"
    + b"  if type(v) is str:\n"
    + b"   q=v.encode('utf-8');return H(3,len(q))+q\n"
    + b"  return H(4,len(v))+b''.join([A(z) for z in v])\n"
)


def _entry(body: str = "return A([631302,1,0,x])") -> bytes:
    return _CANONICALIZER_PREFIX + (" " + body + "\n").encode("ascii")


def _entry_lines(lines: list[str]) -> bytes:
    body = "\n".join(" " + line for line in lines)
    return _CANONICALIZER_PREFIX + (body + "\n").encode("ascii")


def _bundle(
    entry_source: bytes,
    *,
    extra: list[tuple[str, bytes]] | None = None,
) -> tuple[list[object], dict[str, bytes]]:
    files = {
        "evaluation_v6_3_1/__init__.py": b"",
        ENTRY_PATH: entry_source,
        WORKER_PATH: WORKER.read_bytes(),
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
        pytest.skip("the worker profile requires Linux /proc/self/exe")
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


def _input(entry_source: bytes, *, extra: list[tuple[str, bytes]] | None = None) -> bytes:
    manifest, files = _bundle(entry_source, extra=extra)
    profile, root = _profile(manifest, files)
    artifact = _artifact(profile, root, manifest)
    rows = [[row[0], files[row[0]]] for row in manifest[2]]
    payload = _cbor([631302, 1, profile, rows, artifact])
    return b"V631DI01" + len(payload).to_bytes(8, "big") + payload


def _run(payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-E",
            "-s",
            "-P",
            "-B",
            "-u",
            "-X",
            "utf8",
            "-c",
            WORKER.read_text(encoding="ascii"),
            "V631302_DIAGNOSTIC_WORKER_V1",
            WORKER_PATH,
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env={},
        check=False,
    )


def _assert_inventory_failure(result: subprocess.CompletedProcess[bytes]) -> None:
    assert result.returncode == 80
    assert result.stdout == b""
    assert result.stderr == b""


def _assert_success(result: subprocess.CompletedProcess[bytes]) -> bytes:
    assert result.returncode == 0
    assert result.stderr == b""
    assert result.stdout[:8] == b"V631DO01"
    size = int.from_bytes(result.stdout[8:16], "big")
    assert len(result.stdout) == 16 + size
    return result.stdout[16:]


@pytest.fixture(scope="module")
def _worker_verifier() -> tuple[object, type[BaseException]]:
    source = WORKER.read_text(encoding="ascii")
    prefix, marker, _ = source.partition("\ntry:\n    _run()\n")
    assert marker
    namespace: dict[str, object] = {}
    exec(compile(prefix, str(WORKER), "exec"), namespace, namespace)
    return namespace["_verify_code_units"], namespace["_InventoryFailure"]  # type: ignore[return-value]


class _SyntheticCode:
    def __init__(self, raw: bytes) -> None:
        self.co_code = raw
        self.co_names: tuple[str, ...] = ()
        self.co_consts: tuple[object, ...] = ()


def _assert_verifier_rejects(
    verifier: tuple[object, type[BaseException]],
    raw: bytes,
    *,
    names: tuple[str, ...] = (),
    constants: tuple[object, ...] = (),
    varnames: tuple[str, ...] = (),
    cellvars: tuple[str, ...] = (),
    freevars: tuple[str, ...] = (),
) -> None:
    verify, failure = verifier
    record = _SyntheticCode(raw)
    with pytest.raises(failure):
        verify(  # type: ignore[operator]
            record.co_code,
            names,
            constants,
            varnames,
            cellvars,
            freevars,
        )


def _assert_verifier_accepts(
    verifier: tuple[object, type[BaseException]],
    raw: bytes,
) -> None:
    verify, _ = verifier
    assert verify(raw, (), (), (), (), ()) is None  # type: ignore[operator]


def _raw_instruction(name: str, argument: int = 0, cache_units: int = 0) -> bytes:
    assert 0 <= argument <= 0xFF
    return bytes((dis.opmap[name], argument)) + b"\x00\x00" * cache_units


@pytest.mark.parametrize(
    "body",
    [
        "_ = len.__self__; return A([631302,1,0,x])",
        "_ = __import__.__globals__; return A([631302,1,0,x])",
        "_ = __builtins__['open']; return A([631302,1,0,x])",
        "import sys; _ = sys.modules; return A([631302,1,0,x])",
        "_ = globals(); return A([631302,1,0,x])",
        "_ = locals(); return A([631302,1,0,x])",
        "_ = vars(); return A([631302,1,0,x])",
        "_ = dir(); return A([631302,1,0,x])",
        "_ = getattr; return A([631302,1,0,x])",
        "_ = setattr; return A([631302,1,0,x])",
        "_ = delattr; return A([631302,1,0,x])",
        "_ = hasattr; return A([631302,1,0,x])",
        "_ = eval; return A([631302,1,0,x])",
        "_ = exec; return A([631302,1,0,x])",
        "_ = compile; return A([631302,1,0,x])",
        "_ = open; return A([631302,1,0,x])",
    ],
)
def test_builtin_capability_escape_fails_before_project_execution(body: str) -> None:
    """Amendment 5 tests 1-16: no copied-real-builtin escape is executable."""
    _assert_inventory_failure(_run(_input(_entry(body))))


def test_reserved_global_module_delete_and_restore_fails_closed() -> None:
    _assert_inventory_failure(
        _run(
            _input(
                _entry_lines(
                    [
                        f"old = {RESERVED}",
                        f"del {RESERVED}",
                        f"{RESERVED} = old",
                        "return A([631302,1,0,x])",
                    ]
                )
            )
        )
    )


def test_reserved_global_module_rebind_and_restore_fails_closed() -> None:
    _assert_inventory_failure(
        _run(
            _input(
                _entry_lines(
                    [
                        f"old = {RESERVED}",
                        f"{RESERVED} = bytes(bytearray({RESERVED}))",
                        f"{RESERVED} = old",
                        "return A([631302,1,0,x])",
                    ]
                )
            )
        )
    )


def _nested_mutation_lines(invocation: str) -> list[str]:
    return [
        "def mutate():",
        f" global {RESERVED}",
        f" old = {RESERVED}",
        f" {RESERVED} = bytes(bytearray({RESERVED}))",
        f" {RESERVED} = old",
        invocation,
        "return A([631302,1,0,x])",
    ]


@pytest.mark.parametrize(
    "invocation",
    [
        "mutate()",
        "runner = lambda: mutate(); runner()",
        "[mutate() for _ in [0]]",
    ],
)
def test_reserved_global_nested_lambda_and_comprehension_writes_fail_closed(invocation: str) -> None:
    """Amendment 5 tests 19-21: recursive code validation precedes checkpoints."""
    _assert_inventory_failure(_run(_input(_entry_lines(_nested_mutation_lines(invocation)))))


def test_reserved_global_extended_arg_store_fails_closed() -> None:
    fillers = [f"_global_name_{index:03d}" for index in range(300)]
    lines = [
        "def mutate():",
        " global " + ", ".join(fillers + [RESERVED]),
    ]
    lines.extend(f" {name} = {index}" for index, name in enumerate(fillers))
    lines.extend(
        [
            f" old = {RESERVED}",
            f" {RESERVED} = bytes(bytearray({RESERVED}))",
            f" {RESERVED} = old",
            "mutate()",
            "return A([631302,1,0,x])",
        ]
    )
    source = _entry_lines(lines)
    code = compile(source, "amendment-5-extended-arg.py", "exec", dont_inherit=True)
    code_objects = [code]
    index = 0
    while index < len(code_objects):
        current = code_objects[index]
        code_objects.extend(
            constant for constant in current.co_consts if hasattr(constant, "co_code")
        )
        index += 1
    target_stores = [
        instruction
        for current in code_objects
        for instruction in dis.get_instructions(current)
        if instruction.opname == "STORE_GLOBAL" and instruction.argval == RESERVED
    ]
    assert target_stores and any(instruction.arg > 255 for instruction in target_stores)
    _assert_inventory_failure(_run(_input(source)))


def test_hidden_nested_reserved_write_is_rejected_before_execution() -> None:
    source = _entry_lines(
        [
            "if False:",
            " def hidden():",
            f"  global {RESERVED}",
            f"  old = {RESERVED}",
            f"  {RESERVED} = old",
            "return A([631302,1,0,x])",
        ]
    )
    _assert_inventory_failure(_run(_input(source)))


def test_reserved_global_indirect_entry_namespace_store_fails_closed() -> None:
    source = _entry_lines(
        [
            f"g = canonicalize_diagnostic_census_v1.__globals__",
            f"old = g[{RESERVED!r}]",
            f"g[{RESERVED!r}] = bytes(bytearray(old))",
            f"g[{RESERVED!r}] = old",
            "return A([631302,1,0,x])",
        ]
    )
    _assert_inventory_failure(_run(_input(source)))


def test_dependency_absolute_import_of_entry_fails_closed() -> None:
    helper = b"import evaluation_v6_3_1.m0_diagnostic_census\nmarker = 1\n"
    entry = _entry_lines(
        [
            "from .helper import marker",
            "return A([631302,1,0,x])",
        ]
    )
    _assert_inventory_failure(_run(_input(entry, extra=[("evaluation_v6_3_1/helper.py", helper)])))


def test_dependency_relative_import_of_entry_fails_closed() -> None:
    helper = b"from . import m0_diagnostic_census\nmarker = 1\n"
    entry = _entry_lines(
        [
            "from .helper import marker",
            "return A([631302,1,0,x])",
        ]
    )
    _assert_inventory_failure(_run(_input(entry, extra=[("evaluation_v6_3_1/helper.py", helper)])))


@pytest.mark.parametrize(
    "helper",
    [
        b"import evaluation_v6_3_1\nmarker = evaluation_v6_3_1.m0_diagnostic_census\n",
        b"import evaluation_v6_3_1\nmarker = evaluation_v6_3_1.__dict__['m0_diagnostic_census']\n",
        b"import evaluation_v6_3_1\nmarker = evaluation_v6_3_1.m0_diagnostic_census.V631302_BOUND_COLLECTOR_PROFILE_CBOR\n",
    ],
)
def test_dependency_package_attribute_cache_and_ambient_profile_access_fail_closed(helper: bytes) -> None:
    entry = _entry_lines(
        [
            "from .helper import marker",
            "return A([631302,1,0,x])",
        ]
    )
    _assert_inventory_failure(_run(_input(entry, extra=[("evaluation_v6_3_1/helper.py", helper)])))


def test_explicit_profile_argument_propagation_remains_accepted() -> None:
    helper = (
        b"def touch(profile, raw):\n"
        b" if type(profile) is not bytes:\n"
        b"  raise ValueError()\n"
        b" return raw\n"
    )
    entry = _entry_lines(
        [
            "from .helper import touch",
            f"touch({RESERVED}, x)",
            "return A([631302,1,0,x])",
        ]
    )
    _assert_success(_run(_input(entry, extra=[("evaluation_v6_3_1/helper.py", helper)])))


@pytest.mark.parametrize(
    "body",
    [
        "def hidden():\n return len.__self__",
        "def hidden():\n return x.__class__",
        "def hidden():\n return globals()",
    ],
)
def test_recursive_nested_code_is_verified_before_execution(body: str) -> None:
    lines = body.splitlines() + ["return A([631302,1,0,x])"]
    _assert_inventory_failure(_run(_input(_entry_lines(lines))))


def test_malformed_extended_arg_chain_is_rejected(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    extended_arg = dis.opmap["EXTENDED_ARG"]
    return_value = dis.opmap["RETURN_VALUE"]
    raw = bytes((extended_arg, 0)) * 4 + bytes((return_value, 0))
    _assert_verifier_rejects(_worker_verifier, raw)


def test_dangling_extended_arg_is_rejected(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    _assert_verifier_rejects(
        _worker_verifier,
        bytes((dis.opmap["EXTENDED_ARG"], 0)),
    )


def test_unknown_opcode_is_rejected(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    _assert_verifier_rejects(_worker_verifier, bytes((255, 0)))


def test_truncated_code_unit_is_rejected(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    _assert_verifier_rejects(_worker_verifier, bytes((dis.opmap["RETURN_VALUE"],)))


def test_truncated_cache_run_is_rejected(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    _assert_verifier_rejects(
        _worker_verifier,
        bytes((dis.opmap["LOAD_ATTR"], 0, 0, 0)),
    )


def test_standalone_cache_unit_is_rejected(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    _assert_verifier_rejects(_worker_verifier, bytes((dis.opmap["CACHE"], 0)))


def test_no_argument_opcode_rejects_nonzero_argument_byte(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    _assert_verifier_rejects(
        _worker_verifier,
        bytes((dis.opmap["RETURN_VALUE"], 1)),
    )


def test_extended_forward_jump_uses_opcode_offset_as_cpython_does(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    raw = (
        _raw_instruction("EXTENDED_ARG", 1)
        + _raw_instruction("JUMP_FORWARD", 0)
        + _raw_instruction("NOP") * 254
        + _raw_instruction("BINARY_OP", 0, cache_units=1)
        + _raw_instruction("RETURN_VALUE")
    )
    _assert_verifier_accepts(_worker_verifier, raw)


@pytest.mark.parametrize(
    ("raw", "metadata"),
    [
        (_raw_instruction("LOAD_NAME"), {}),
        (_raw_instruction("IMPORT_NAME"), {}),
        (_raw_instruction("LOAD_GLOBAL", cache_units=5), {}),
        (_raw_instruction("LOAD_ATTR", cache_units=4), {}),
        (_raw_instruction("LOAD_CONST"), {}),
        (_raw_instruction("KW_NAMES"), {}),
        (_raw_instruction("LOAD_FAST"), {}),
        (_raw_instruction("MAKE_CELL"), {}),
        (_raw_instruction("LOAD_DEREF"), {}),
        (_raw_instruction("COPY_FREE_VARS", 1), {}),
    ],
)
def test_out_of_range_operand_indices_fail_closed(
    _worker_verifier: tuple[object, type[BaseException]],
    raw: bytes,
    metadata: dict[str, tuple[object, ...]],
) -> None:
    _assert_verifier_rejects(_worker_verifier, raw, **metadata)  # type: ignore[arg-type]


def test_kw_names_rejects_non_string_constant_tuple(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    _assert_verifier_rejects(
        _worker_verifier,
        _raw_instruction("KW_NAMES"),
        constants=(("ok", 1),),
    )


def test_copy_free_vars_requires_exact_free_variable_count(
    _worker_verifier: tuple[object, type[BaseException]],
) -> None:
    _assert_verifier_rejects(
        _worker_verifier,
        _raw_instruction("COPY_FREE_VARS", 0),
        freevars=("captured",),
    )


@pytest.mark.parametrize(
    "lines",
    [
        ["def hidden():", " yield 1", "return A([631302,1,0,x])"],
        ["def hidden():", ' return f"{x}"', "return A([631302,1,0,x])"],
        ["def hidden():", " with x:", "  pass", "return A([631302,1,0,x])"],
        ["def hidden():", " assert x", "return A([631302,1,0,x])"],
        ["class Hidden:", " pass", "return A([631302,1,0,x])"],
    ],
)
def test_forbidden_opcode_forms_fail_before_project_execution(lines: list[str]) -> None:
    _assert_inventory_failure(_run(_input(_entry_lines(lines))))


@pytest.mark.parametrize(
    "body",
    [
        "def hidden():\n return x.__class__",
        "def hidden():\n return x.__dict__",
        "def hidden():\n return x.__mro__",
    ],
)
def test_forbidden_attribute_operands_fail_before_project_execution(body: str) -> None:
    _assert_inventory_failure(_run(_input(_entry_lines(body.splitlines() + ["return A([631302,1,0,x])"]))))


@pytest.mark.parametrize(
    "body",
    [
        "def hidden():\n return globals()",
        "def hidden():\n return __builtins__",
        "def hidden():\n return __import__",
    ],
)
def test_forbidden_global_name_operands_fail_before_project_execution(body: str) -> None:
    _assert_inventory_failure(_run(_input(_entry_lines(body.splitlines() + ["return A([631302,1,0,x])"]))))
