from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from evaluation_v6_3_1.eir_prebinding import (
    ENVIRONMENT,
    FIXED_TARGET_ROOT,
    EIRPrebindingError,
    compiler_semantics_root,
    eir_canonical_cbor_encode,
    toolchain_runtime_root,
)
from evaluation_v6_3_1.eir_runtime_bundle import build_toolchain_runtime_manifest
from evaluation_v6_3_1.eir_state3_namespace import (
    STATE3_DEFINITION_SPAN_UNBOUND,
    STATE3_EFFECTIVE_FRONTEND_MISMATCH,
    STATE3_NAMESPACE_IMMUTABILITY_UNAVAILABLE,
    STATE3_PREDEFINES_MISMATCH,
    STATE3_RUNTIME_INPUT_UNMANIFESTED,
    bind_tu_observation_to_namespace,
)
from evaluation_v6_3_1.eir_state3_semantics import (
    decode_extractor_tu_observation_v2_bytes,
    source_tree_sha256,
)


def _error(code: str, function, *args, **kwargs) -> None:
    with pytest.raises(EIRPrebindingError) as raised:
        function(*args, **kwargs)
    assert raised.value.code == code


def _fixture(tmp_path: Path) -> dict[str, object]:
    source = tmp_path / "source"
    source.mkdir()
    engine_bytes = b"void helper() {}\n"
    (source / "engine.cc").write_bytes(engine_bytes)
    (source / "dep.h").write_bytes(b"#pragma once\n")
    source_root = source_tree_sha256(source)

    runtime = tmp_path / "runtime"
    compiler_file = runtime / "v631302" / "toolchain" / "bin" / "clang"
    extractor_file = runtime / "v631302" / "toolchain" / "bin" / "extractor"
    runtime_header = runtime / "v631302" / "toolchain" / "include" / "rt.h"
    resource_dir = runtime / "v631302" / "toolchain" / "lib" / "clang" / "16"
    for path in (compiler_file, extractor_file, runtime_header):
        path.parent.mkdir(parents=True, exist_ok=True)
    resource_dir.mkdir(parents=True)
    compiler_bytes = b"\x7fELFcompiler"
    extractor_bytes = b"\x7fELFextractor"
    compiler_file.write_bytes(compiler_bytes)
    extractor_file.write_bytes(extractor_bytes)
    runtime_header.write_bytes(b"runtime header\n")
    compiler_file.chmod(0o755)
    extractor_file.chmod(0o755)

    compiler_path = "/v631302/toolchain/bin/clang"
    extractor_path = "/v631302/toolchain/bin/extractor"
    runtime_header_path = "/v631302/toolchain/include/rt.h"
    runtime_manifest = build_toolchain_runtime_manifest(
        runtime,
        compiler_entry_path=compiler_path,
        extractor_entry_path=extractor_path,
        runtime_platform=["linux-gnu", "amd64", 1, 64, 8],
    )
    runtime_root = toolchain_runtime_root(runtime_manifest)
    compiler_digest = sha256(compiler_bytes).digest()
    extractor_digest = sha256(extractor_bytes).digest()
    primary = "/v631302/src/engine.cc"
    semantics = [
        2,
        runtime_root,
        source_root,
        "/v631302/work",
        "/v631302/src",
        "/v631302/toolchain",
        deepcopy(ENVIRONMENT),
        [
            1,
            0,
            0,
            0,
            0,
            [
                [1, compiler_path, compiler_digest],
                [2, extractor_path, extractor_digest],
            ],
        ],
        [
            [
                0,
                primary,
                [compiler_path, "-c", primary],
                [extractor_path, primary],
            ]
        ],
    ]
    semantics_root = compiler_semantics_root(semantics)
    frontend = [
        [compiler_path, "-cc1", "-triple", "x86_64-unknown-linux-gnu", primary],
        "x86_64-unknown-linux-gnu",
        2,
        "c++20",
        "/v631302/toolchain/lib/clang/16",
        "",
        0,
        0,
        0,
        0,
        0,
    ]
    predefines = b"#define __cplusplus 202002L\n"
    virtual = [[0, 1, "<built-in>", b"built-in buffer", 1]]
    definitions = [
        [
            0,
            "FunctionDecl",
            "helper",
            "void ()",
            1,
            [],
            primary,
            0,
            len(engine_bytes),
            [],
        ]
    ]
    observation = [
        631302,
        2,
        0,
        primary,
        frontend,
        [1, primary, 1],
        [
            [0, 1, "/v631302/src/dep.h", 1],
            [1, 2, runtime_header_path, 1],
        ],
        predefines,
        virtual,
        definitions,
        [3, 3, 3, 3, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0],
    ]
    observation_bytes = eir_canonical_cbor_encode(observation)
    kwargs = {
        "source_rootfs": source,
        "runtime_rootfs": runtime,
        "expected_source_root": source_root,
        "expected_target_root": FIXED_TARGET_ROOT,
        "expected_toolchain_runtime_root": runtime_root,
        "expected_compiler_binary_sha256": compiler_digest,
        "expected_extractor_binary_sha256": extractor_digest,
        "expected_compiler_semantics_root": semantics_root,
        "toolchain_runtime_manifest": runtime_manifest,
        "compiler_semantics_manifest": semantics,
        "executor_effective_frontend_state": frontend,
        "executor_predefines_bytes": predefines,
        "executor_virtual_input_observations": virtual,
    }
    return {
        "observation": observation,
        "observation_bytes": observation_bytes,
        "kwargs": kwargs,
        "engine_bytes": engine_bytes,
    }


def _offline_readonly_mount_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit fixtures exercise binding math without claiming real mount custody."""

    monkeypatch.setattr(
        "evaluation_v6_3_1.eir_state3_namespace._require_readonly_mount",
        lambda *_args, **_kwargs: None,
    )


def test_namespace_binding_reopens_inputs_and_derives_only_zero_authority_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    _offline_readonly_mount_fixture(monkeypatch)

    result = bind_tu_observation_to_namespace(
        fixture["observation_bytes"], **fixture["kwargs"]
    )

    assert result.state == "NAMESPACE_BOUND_TU_PRIMITIVE"
    assert len(result.tu_content_root) == 32
    assert len(result.tu_semantics_root) == 32
    assert len(result.linkage_scope_id) == 32
    assert result.primary_input_commitment[2] == len(fixture["engine_bytes"])
    assert len(result.dependency_commitments) == 2
    assert not result.compiler_recomputed
    assert not result.authority
    assert not result.agent_modification_authority
    assert not result.calibration_upload_authority
    assert not result.production_upload_authority
    assert not result.sealed_holdout_access_authority


def test_raw_observation_decoder_rejects_stdout_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    _offline_readonly_mount_fixture(monkeypatch)
    raw = eir_canonical_cbor_encode(fixture["observation"])
    assert decode_extractor_tu_observation_v2_bytes(raw) == fixture["observation"]
    _error(
        "PREBINDING_CANONICAL_ENCODING",
        decode_extractor_tu_observation_v2_bytes,
        raw + b"diagnostic",
    )
    _error(
        "PREBINDING_CANONICAL_ENCODING",
        bind_tu_observation_to_namespace,
        raw + b"diagnostic",
        **fixture["kwargs"],
    )


def test_namespace_binding_rejects_mutable_filesystems_before_observation_use(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _error(
        STATE3_NAMESPACE_IMMUTABILITY_UNAVAILABLE,
        bind_tu_observation_to_namespace,
        fixture["observation_bytes"],
        **fixture["kwargs"],
    )


def test_namespace_binding_rejects_writable_nested_mount_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    source_root = fixture["kwargs"]["source_rootfs"]
    nested = source_root / "nested"
    nested.mkdir()
    (nested / "mutable.txt").write_bytes(b"mutable")
    nested_stat = nested.stat()

    def mount_policy(root_fd: int):
        opened = os.fstat(root_fd)
        is_nested = (opened.st_dev, opened.st_ino) == (nested_stat.st_dev, nested_stat.st_ino)
        return SimpleNamespace(f_flag=0 if is_nested else os.ST_RDONLY)

    monkeypatch.setattr(
        "evaluation_v6_3_1.eir_state3_namespace.os.fstatvfs",
        mount_policy,
    )
    _error(
        STATE3_NAMESPACE_IMMUTABILITY_UNAVAILABLE,
        bind_tu_observation_to_namespace,
        fixture["observation_bytes"],
        **fixture["kwargs"],
    )


def test_namespace_binding_retains_root_fds_across_ancestor_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = tmp_path / "original"
    original.mkdir()
    fixture = _fixture(original)
    moved = tmp_path / "moved"
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    calls = 0

    def swap_after_both_roots_are_open(*_args, **_kwargs) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            original.rename(moved)
            original.symlink_to(attacker, target_is_directory=True)

    monkeypatch.setattr(
        "evaluation_v6_3_1.eir_state3_namespace._require_readonly_mount",
        swap_after_both_roots_are_open,
    )
    result = bind_tu_observation_to_namespace(
        fixture["observation_bytes"], **fixture["kwargs"]
    )

    assert result.primary_input_commitment[3] == sha256(fixture["engine_bytes"]).digest()
    assert not result.authority


def test_namespace_binding_rejects_executor_comparison_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    _offline_readonly_mount_fixture(monkeypatch)
    frontend_kwargs = deepcopy(fixture["kwargs"])
    frontend_kwargs["executor_effective_frontend_state"][1] = "aarch64-unknown-linux-gnu"
    _error(
        STATE3_EFFECTIVE_FRONTEND_MISMATCH,
        bind_tu_observation_to_namespace,
        fixture["observation_bytes"],
        **frontend_kwargs,
    )

    predefines_kwargs = deepcopy(fixture["kwargs"])
    predefines_kwargs["executor_predefines_bytes"] = b"different"
    _error(
        STATE3_PREDEFINES_MISMATCH,
        bind_tu_observation_to_namespace,
        fixture["observation_bytes"],
        **predefines_kwargs,
    )


def test_namespace_binding_rejects_unmanifested_runtime_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    _offline_readonly_mount_fixture(monkeypatch)
    observation = deepcopy(fixture["observation"])
    observation[6][1][2] = "/v631302/toolchain/include/missing.h"
    _error(
        STATE3_RUNTIME_INPUT_UNMANIFESTED,
        bind_tu_observation_to_namespace,
        eir_canonical_cbor_encode(observation),
        **fixture["kwargs"],
    )


def test_namespace_binding_rejects_definition_span_outside_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    _offline_readonly_mount_fixture(monkeypatch)
    observation = deepcopy(fixture["observation"])
    observation[9][0][8] = len(fixture["engine_bytes"]) + 1
    _error(
        STATE3_DEFINITION_SPAN_UNBOUND,
        bind_tu_observation_to_namespace,
        eir_canonical_cbor_encode(observation),
        **fixture["kwargs"],
    )
