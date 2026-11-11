from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import shutil
import subprocess

import pytest

from evaluation_v6_3_1.launch_gate_dependency_manifest_v1 import (
    AGENT_MODIFICATION_AUTHORITY,
    AUTHORITY,
    CALIBRATION_UPLOAD_AUTHORITY,
    DEPENDENCY_CBOR,
    DEPENDENCY_DUPLICATE,
    DEPENDENCY_EMPTY,
    DEPENDENCY_ENCODING,
    DEPENDENCY_HASH,
    DEPENDENCY_INVALID_TYPE,
    DEPENDENCY_ORDER,
    DEPENDENCY_PATH,
    DEPENDENCY_RESOURCE_LIMIT,
    DEPENDENCY_SCHEMA,
    DEPENDENCY_SYNTAX,
    DEPENDENCY_TARGET,
    DEPENDENCY_TOKEN,
    HOLDOUT_ACCESS_AUTHORITY,
    LLVM_HEADER_ROOTS,
    PERMIT_AUTHORITY,
    PRODUCTION_UPLOAD_AUTHORITY,
    TARGET_NAME_BYTES,
    UPLOAD_AUTHORITY,
    DependencyManifestV1,
    DependencyRowV1,
    LaunchGateDependencyManifestError,
    SymlinkRowV1,
    WIRE_VERSION,
    build_dependency_manifest_v1,
    decode_dependency_manifest_v1,
    eir_canonical_cbor_decode,
    encode_dependency_manifest_v1,
    lexical_absolute_dependency_path,
    parse_make_dependency_file_v1,
    zero_authority_status,
)


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"


def _error(function, *args, **kwargs) -> LaunchGateDependencyManifestError:
    with pytest.raises(LaunchGateDependencyManifestError) as raised:
        function(*args, **kwargs)
    return raised.value


def _row(path: bytes = b"/work/a.h", *, link: bool = False) -> DependencyRowV1:
    chain: tuple[SymlinkRowV1, ...] = ()
    if link:
        target = b"../real/a.h"
        symlink = SymlinkRowV1(
            b"/work/link/a.h",
            target,
            sha256(target).digest(),
        )
        chain = (symlink,)
    return DependencyRowV1(path, path, 7, sha256(path).digest(), chain)


def _manifest_value() -> list[object]:
    return eir_canonical_cbor_decode(
        encode_dependency_manifest_v1(
            build_dependency_manifest_v1((_row(b"/work/a.h"), _row(b"/work/b.h", link=True)))
        )
    )


def test_zero_authority_is_permanent() -> None:
    assert AUTHORITY is False
    assert UPLOAD_AUTHORITY is False
    assert CALIBRATION_UPLOAD_AUTHORITY is False
    assert PRODUCTION_UPLOAD_AUTHORITY is False
    assert PERMIT_AUTHORITY is False
    assert HOLDOUT_ACCESS_AUTHORITY is False
    assert AGENT_MODIFICATION_AUTHORITY is False
    assert all(value is False for key, value in zero_authority_status().items() if key != "state")


def test_parser_accepts_exact_target_and_continuation() -> None:
    parsed = parse_make_dependency_file_v1(
        TARGET_NAME_BYTES
        + b": /opt/llvm-build/include/a.h ./src/one.h "
        + b"\\\n"
        + b"  ../src/two.h"
    )
    assert parsed.target == TARGET_NAME_BYTES
    assert parsed.dependency_tokens == (
        b"/opt/llvm-build/include/a.h",
        b"./src/one.h",
        b"../src/two.h",
    )
    assert parsed.lexical_absolute_paths == (
        b"/opt/llvm-build/include/a.h",
        b"/work/src/one.h",
        b"/src/two.h",
    )


def test_parser_preserves_token_boundary_across_continuation_and_terminal_lf() -> None:
    parsed = parse_make_dependency_file_v1(TARGET_NAME_BYTES + b": a.h\\\nb.h\n")
    assert parsed.dependency_tokens == (b"a.h", b"b.h")
    assert parsed.lexical_absolute_paths == (b"/work/a.h", b"/work/b.h")


@pytest.mark.docker_smoke
def test_parser_consumes_real_pinned_clang16_dependency_output(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker is unavailable")
    inspected = subprocess.run(
        ["docker", "image", "inspect", IMAGE, "--format", "{{.Id}} {{.Architecture}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if inspected.returncode != 0 or inspected.stdout.strip() != f"{IMAGE} amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    source = "/repo/evaluation_v6_3_1/native/capture_v2/tools/launch_gate_llvm_mc_decoder_v1.cpp"
    command = (
        "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC "
        "SOURCE_DATE_EPOCH=0 HOME=/nonexistent DEBUGINFOD_URLS= TMPDIR=/tmp "
        "/usr/bin/clang++-16 --target=x86_64-unknown-linux-gnu -std=c++20 -O2 "
        "-fPIE -fno-lto -fno-exceptions -fno-rtti -fno-ident -fvisibility=hidden "
        "-ffile-prefix-map=/repo=. -fmacro-prefix-map=/repo=. -MD "
        "-MF /out/dependencies.d.raw -MT launch_gate_llvm_mc_decoder_v1.o "
        "-I/opt/llvm-build/include -I/opt/llvm-src/llvm/include "
        f"-c {source} -o /tmp/decoder.o"
    )
    result = subprocess.run(
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
            f"type=bind,src={tmp_path},dst=/out",
            IMAGE,
            "/bin/sh",
            "-c",
            command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr
    raw = (tmp_path / "dependencies.d.raw").read_bytes()
    assert raw.endswith(b"\n")
    assert b"\\\n" in raw
    parsed = parse_make_dependency_file_v1(raw)
    assert parsed.target == TARGET_NAME_BYTES
    assert len(parsed.dependency_tokens) > 100
    assert len(parsed.dependency_tokens) == len(set(parsed.lexical_absolute_paths))


@pytest.mark.parametrize(
    "token, expected",
    [
        (b"header.h", b"/work/header.h"),
        (b"./a//b/../c.h", b"/work/a/c.h"),
        (b"/a/./b/../c.h", b"/a/c.h"),
        (b"../../outside.h", b"/outside.h"),
        (b"/", b"/"),
    ],
)
def test_lexical_paths_are_normalized_without_filesystem_access(token: bytes, expected: bytes) -> None:
    assert lexical_absolute_dependency_path(token) == expected


@pytest.mark.parametrize(
    "raw, code",
    [
        (TARGET_NAME_BYTES + b": a.h\n b.h", DEPENDENCY_SYNTAX),
        (TARGET_NAME_BYTES + b": a.h\\t b.h", DEPENDENCY_SYNTAX),
        (TARGET_NAME_BYTES + b": a.h\\\\ b.h", DEPENDENCY_SYNTAX),
        (TARGET_NAME_BYTES + b": a.h\\", DEPENDENCY_SYNTAX),
        (b"other.o: a.h", DEPENDENCY_TARGET),
        (TARGET_NAME_BYTES + b" a.o: a.h", DEPENDENCY_TARGET),
        (TARGET_NAME_BYTES + b":", DEPENDENCY_EMPTY),
        (TARGET_NAME_BYTES + b": " + b"\\\n", DEPENDENCY_SYNTAX),
        (TARGET_NAME_BYTES + b": a.h #comment", DEPENDENCY_TOKEN),
        (TARGET_NAME_BYTES + b": a$.h", DEPENDENCY_TOKEN),
        (TARGET_NAME_BYTES + b": a:b.h", DEPENDENCY_SYNTAX),
        (TARGET_NAME_BYTES + b": a.h a.h", DEPENDENCY_DUPLICATE),
        (TARGET_NAME_BYTES + b": a.h ./a.h", DEPENDENCY_DUPLICATE),
        (TARGET_NAME_BYTES + b": a\xc2\xa0b.h", DEPENDENCY_TOKEN),
        (b"\xff", DEPENDENCY_ENCODING),
        (TARGET_NAME_BYTES + b"\x00: a.h", DEPENDENCY_ENCODING),
    ],
)
def test_parser_rejects_syntax_and_token_mutations(raw: bytes, code: str) -> None:
    error = _error(parse_make_dependency_file_v1, raw)
    assert error.code == code


def test_parser_enforces_dependency_count_while_tokenizing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "evaluation_v6_3_1.launch_gate_dependency_manifest_v1.MAX_DEPENDENCY_ENTRIES",
        2,
    )
    error = _error(parse_make_dependency_file_v1, TARGET_NAME_BYTES + b": a.h b.h c.h")
    assert error.code == DEPENDENCY_RESOURCE_LIMIT


def test_schema_rows_are_immutable_and_canonical() -> None:
    link_target = b"../real/a.h"
    symlink = SymlinkRowV1(b"/work/link/a.h", link_target, sha256(link_target).digest())
    row = DependencyRowV1(
        b"/work/link/a.h",
        b"/work/real/a.h",
        0,
        bytes(32),
        (symlink,),
    )
    assert row.as_array() == [
        b"/work/link/a.h",
        b"/work/real/a.h",
        0,
        bytes(32),
        [[b"/work/link/a.h", link_target, sha256(link_target).digest()]],
    ]
    with pytest.raises((AttributeError, TypeError)):
        row.byte_length = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    "factory, args, code",
    [
        (SymlinkRowV1, ("/work/link", b"x", sha256(b"x").digest()), "type"),
        (SymlinkRowV1, (b"/work/link", b"x", bytes(31)), DEPENDENCY_HASH),
        (SymlinkRowV1, (b"/work/link", b"x", bytes(32)), DEPENDENCY_HASH),
        (SymlinkRowV1, (b"/work/./link", b"x", sha256(b"x").digest()), DEPENDENCY_PATH),
        (SymlinkRowV1, (b"/work/link", b"x\x00", sha256(b"x\x00").digest()), DEPENDENCY_SCHEMA),
        (DependencyRowV1, (b"work/a", b"/work/a", 1, bytes(32), ()), DEPENDENCY_PATH),
        (DependencyRowV1, (b"/work/a", b"/work/a", -1, bytes(32), ()), DEPENDENCY_SCHEMA),
        (DependencyRowV1, (b"/work/a", b"/work/a", 1, bytes(31), ()), DEPENDENCY_HASH),
        (DependencyRowV1, (b"/work/a", b"/work/a", 1, bytes(32), []), "type"),
    ],
)
def test_schema_field_mutations_fail_closed(factory, args, code: str) -> None:
    error = _error(factory, *args)
    if code == "type":
        assert error.code == "DEPENDENCY_INVALID_TYPE"
    else:
        assert error.code == code


def test_symlink_chain_duplicate_and_hash_mutations_fail() -> None:
    target = b"real"
    symlink = SymlinkRowV1(b"/work/link", target, sha256(target).digest())
    _error(
        DependencyRowV1,
        b"/work/link",
        b"/work/real",
        1,
        bytes(32),
        (symlink, symlink),
    )


def test_manifest_requires_exact_sorted_unique_entries_and_header_order() -> None:
    error = _error(build_dependency_manifest_v1, ())
    assert error.code == DEPENDENCY_EMPTY
    _error(build_dependency_manifest_v1, (_row(b"/work/b"), _row(b"/work/a")))
    _error(build_dependency_manifest_v1, (_row(b"/work/a"), _row(b"/work/a")))
    value = _manifest_value()
    value[2] = [LLVM_HEADER_ROOTS[1], LLVM_HEADER_ROOTS[0]]
    error = _error(DependencyManifestV1.from_array, value)
    assert error.code == DEPENDENCY_SCHEMA


@pytest.mark.parametrize(
    "mutate, code",
    [
        (lambda value: value.__setitem__(0, 631303), DEPENDENCY_SCHEMA),
        (lambda value: value.__setitem__(1, 2), DEPENDENCY_SCHEMA),
        (lambda value: value.__setitem__(2, [b"/opt/llvm-build/include", b"/wrong"]), DEPENDENCY_SCHEMA),
        (lambda value: value[3][0].__setitem__(2, -1), DEPENDENCY_SCHEMA),
        (lambda value: value[3][0].__setitem__(3, bytes(31)), DEPENDENCY_HASH),
        (lambda value: value[3][0].__setitem__(0, "/work/a"), DEPENDENCY_INVALID_TYPE),
        (lambda value: value[3][1][4].append(value[3][1][4][0]), DEPENDENCY_DUPLICATE),
        (lambda value: value[3].reverse(), "order"),
        (lambda value: value.__setitem__(3, value[3] + [deepcopy(value[3][0])]), DEPENDENCY_ORDER),
        (lambda value: value[3][1].__setitem__(4, "not-array"), DEPENDENCY_SCHEMA),
    ],
)
def test_manifest_array_mutations_fail_closed(mutate, code: str) -> None:
    value = _manifest_value()
    mutate(value)
    error = _error(DependencyManifestV1.from_array, value)
    if code == "order":
        assert error.code == DEPENDENCY_ORDER
    else:
        assert error.code == code


def test_canonical_manifest_round_trip_is_byte_identical() -> None:
    manifest = build_dependency_manifest_v1((_row(b"/work/a.h"), _row(b"/work/b.h", link=True)))
    encoded = encode_dependency_manifest_v1(manifest)
    decoded = decode_dependency_manifest_v1(encoded)
    assert decoded == manifest
    assert encode_dependency_manifest_v1(decoded) == encoded
    value = eir_canonical_cbor_decode(encoded)
    assert value[0:3] == [631302, WIRE_VERSION, list(LLVM_HEADER_ROOTS)]
    assert all(type(root) is bytes for root in value[2])


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x81\x18\x01",  # non-array protocol-shaped CBOR
        encode_dependency_manifest_v1(build_dependency_manifest_v1((_row(b"/work/a"),))) + b"\x00",
    ],
)
def test_cbor_mutations_fail_closed(raw: bytes) -> None:
    error = _error(decode_dependency_manifest_v1, raw)
    assert error.code == DEPENDENCY_CBOR


def test_cbor_decoder_requires_exact_bytes_type() -> None:
    error = _error(decode_dependency_manifest_v1, bytearray(b"x"))
    assert error.code == DEPENDENCY_INVALID_TYPE
