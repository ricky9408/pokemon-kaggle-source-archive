"""Bind one State3 TU observation to independently read namespace bytes.

This module is a zero-authority executor primitive. It verifies the complete
source and runtime trees, reopens every observed physical frontend input,
compares executor-derived frontend/predefines/virtual-buffer observations, and
derives the TU content, semantics, and linkage roots. It does not run Clang,
establish provenance for the executor-derived comparison values, validate AST
anchor paths, reconstruct global ODR/helper closure, or advance state 2 to
``COMPILER_RECOMPUTED``.
"""

from __future__ import annotations

import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Sequence

from .eir_prebinding import (
    AGENT_MODIFICATION_AUTHORITY,
    AUTHORITY,
    ENGINE_WIRING_AUTHORITY,
    EIRPrebindingError,
    FIXED_TARGET_ROOT,
    HOLDOUT_ACCESS_AUTHORITY,
    PERMIT_AUTHORITY,
    UPLOAD_AUTHORITY,
    compiler_semantics_root,
    eir_canonical_cbor_encode,
    toolchain_runtime_root,
    validate_compiler_semantics_manifest,
    validate_toolchain_runtime_manifest,
)
from .eir_runtime_bundle import (
    DEFAULT_LIMITS as DEFAULT_RUNTIME_LIMITS,
    RuntimeBundleLimits,
    assert_toolchain_runtime_bundle_fd,
)
from .eir_state3_semantics import (
    CALIBRATION_UPLOAD_AUTHORITY,
    DEFAULT_SOURCE_TREE_LIMITS,
    PRODUCTION_UPLOAD_AUTHORITY,
    RUNTIME_ORIGIN,
    SEALED_HOLDOUT_ACCESS_AUTHORITY,
    SOURCE_ORIGIN,
    SourceTreeLimits,
    decode_extractor_tu_observation_v2_bytes,
    linkage_scope_id,
    source_tree_sha256_fd,
    tu_content_root,
    tu_semantics_root,
    validate_effective_frontend_state,
)


STATE3_NAMESPACE_ROOT_INVALID = "STATE3_NAMESPACE_ROOT_INVALID"
STATE3_NAMESPACE_PATH_INVALID = "STATE3_NAMESPACE_PATH_INVALID"
STATE3_NAMESPACE_IO_ERROR = "STATE3_NAMESPACE_IO_ERROR"
STATE3_NAMESPACE_RACE_DETECTED = "STATE3_NAMESPACE_RACE_DETECTED"
STATE3_NAMESPACE_FILE_TOO_LARGE = "STATE3_NAMESPACE_FILE_TOO_LARGE"
STATE3_NAMESPACE_LIMIT_EXCEEDED = "STATE3_NAMESPACE_LIMIT_EXCEEDED"
STATE3_NAMESPACE_IMMUTABILITY_UNAVAILABLE = "STATE3_NAMESPACE_IMMUTABILITY_UNAVAILABLE"
STATE3_RUNTIME_ROOT_MISMATCH = "STATE3_RUNTIME_ROOT_MISMATCH"
STATE3_COMPILER_SEMANTICS_ROOT_MISMATCH = "STATE3_COMPILER_SEMANTICS_ROOT_MISMATCH"
STATE3_EXECUTABLE_DIGEST_MISMATCH = "STATE3_EXECUTABLE_DIGEST_MISMATCH"
STATE3_TU_MANIFEST_MISMATCH = "STATE3_TU_MANIFEST_MISMATCH"
STATE3_EFFECTIVE_FRONTEND_MISMATCH = "STATE3_EFFECTIVE_FRONTEND_MISMATCH"
STATE3_PREDEFINES_MISMATCH = "STATE3_PREDEFINES_MISMATCH"
STATE3_VIRTUAL_INPUT_MISMATCH = "STATE3_VIRTUAL_INPUT_MISMATCH"
STATE3_RUNTIME_INPUT_UNMANIFESTED = "STATE3_RUNTIME_INPUT_UNMANIFESTED"
STATE3_RUNTIME_INPUT_MISMATCH = "STATE3_RUNTIME_INPUT_MISMATCH"
STATE3_DEFINITION_SPAN_UNBOUND = "STATE3_DEFINITION_SPAN_UNBOUND"

_RUNTIME_REGULAR_FILE = 1


@dataclass(frozen=True)
class BoundTUObservation:
    """Derived TU roots and immutable byte commitments; never an authority receipt."""

    tu_ordinal: int
    primary_source_virtual_path: str
    observation_cbor: bytes
    primary_input_commitment: tuple[Any, ...]
    dependency_commitments: tuple[tuple[Any, ...], ...]
    predefines_commitment: tuple[Any, ...]
    virtual_input_commitments: tuple[tuple[Any, ...], ...]
    definition_instance_observations_cbor: bytes
    tu_content_root: bytes
    tu_semantics_root: bytes
    linkage_scope_id: bytes
    state: str = "NAMESPACE_BOUND_TU_PRIMITIVE"
    compiler_recomputed: bool = False
    external_evidence_valid: bool = False
    authority: bool = AUTHORITY
    engine_wiring_authority: bool = ENGINE_WIRING_AUTHORITY
    permit_authority: bool = PERMIT_AUTHORITY
    agent_modification_authority: bool = AGENT_MODIFICATION_AUTHORITY
    calibration_upload_authority: bool = CALIBRATION_UPLOAD_AUTHORITY
    production_upload_authority: bool = PRODUCTION_UPLOAD_AUTHORITY
    sealed_holdout_access_authority: bool = SEALED_HOLDOUT_ACCESS_AUTHORITY
    upload_authority: bool = UPLOAD_AUTHORITY
    holdout_access_authority: bool = HOLDOUT_ACCESS_AUTHORITY


def _fail(code: str, message: str) -> EIRPrebindingError:
    return EIRPrebindingError(code, message)


def _bstr(value: Any, label: str) -> bytes:
    if type(value) is not bytes:
        raise _fail(STATE3_NAMESPACE_PATH_INVALID, f"{label} must be bytes")
    return value


def _bstr32(value: Any, label: str) -> bytes:
    result = _bstr(value, label)
    if len(result) != 32:
        raise _fail(STATE3_NAMESPACE_PATH_INVALID, f"{label} must be exactly 32 bytes")
    return result


def _stat_signature(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _same_stat(before: os.stat_result, after: os.stat_result, label: str) -> None:
    if _stat_signature(before) != _stat_signature(after):
        raise _fail(STATE3_NAMESPACE_RACE_DETECTED, f"physical input changed: {label}")


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _fail(STATE3_NAMESPACE_IO_ERROR, "O_NOFOLLOW is required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_namespace_root(rootfs: os.PathLike[str] | str, label: str) -> int:
    """Open an absolute directory by no-follow traversal and retain its FD."""

    try:
        root_path = os.path.abspath(os.fspath(rootfs))
    except (TypeError, ValueError) as exc:
        raise _fail(STATE3_NAMESPACE_ROOT_INVALID, f"{label} root is invalid: {exc}") from exc
    components = tuple(component for component in root_path.split(os.sep) if component)
    try:
        current_fd = os.open(os.sep, _directory_flags())
    except OSError as exc:
        raise _fail(STATE3_NAMESPACE_IO_ERROR, f"cannot open filesystem root: {exc}") from exc
    try:
        for component in components:
            expected = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(expected.st_mode) or not stat.S_ISDIR(expected.st_mode):
                raise _fail(
                    STATE3_NAMESPACE_ROOT_INVALID,
                    f"{label} root traversal contains a symlink or non-directory",
                )
            next_fd = os.open(component, _directory_flags(), dir_fd=current_fd)
            try:
                _same_stat(expected, os.fstat(next_fd), label)
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except EIRPrebindingError:
        os.close(current_fd)
        raise
    except OSError as exc:
        os.close(current_fd)
        raise _fail(STATE3_NAMESPACE_IO_ERROR, f"cannot traverse {label} root: {exc}") from exc


def _require_readonly_mount(root_fd: int, label: str) -> None:
    """Fail closed unless the retained namespace FD is on a read-only mount."""

    try:
        flags = os.fstatvfs(root_fd).f_flag
    except (TypeError, ValueError, OSError) as exc:
        raise _fail(
            STATE3_NAMESPACE_IMMUTABILITY_UNAVAILABLE,
            f"cannot verify {label} filesystem immutability: {exc}",
        ) from exc
    readonly_flag = getattr(os, "ST_RDONLY", 1)
    if flags & readonly_flag == 0:
        raise _fail(
            STATE3_NAMESPACE_IMMUTABILITY_UNAVAILABLE,
            f"{label} filesystem is not mounted read-only",
        )


def _path_components(relative_path: str, max_path_bytes: int) -> tuple[str, ...]:
    if type(relative_path) is not str or not relative_path:
        raise _fail(STATE3_NAMESPACE_PATH_INVALID, "physical relative path is empty")
    try:
        raw = relative_path.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(STATE3_NAMESPACE_PATH_INVALID, "physical path is not strict UTF-8") from exc
    components = tuple(relative_path.split("/"))
    if len(raw) > max_path_bytes or any(
        not component or component in (".", "..") or "\x00" in component
        for component in components
    ):
        raise _fail(STATE3_NAMESPACE_PATH_INVALID, "physical path is not canonical")
    return components


def _verify_readonly_tree(
    root_fd: int,
    label: str,
    *,
    max_entries: int,
    max_path_bytes: int,
) -> None:
    """Require every directory and regular file below a retained root to be read-only."""

    root_stat = os.fstat(root_fd)
    pending: list[tuple[tuple[str, ...], os.stat_result]] = [((), root_stat)]
    entry_count = 0
    while pending:
        components, expected_directory = pending.pop()
        current_fd = os.dup(root_fd)
        try:
            _require_readonly_mount(current_fd, label)
            for component in components:
                expected = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                next_fd = os.open(component, _directory_flags(), dir_fd=current_fd)
                try:
                    _same_stat(expected, os.fstat(next_fd), label)
                    _require_readonly_mount(next_fd, label)
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(current_fd)
                current_fd = next_fd
            _same_stat(expected_directory, os.fstat(current_fd), label)

            scan_fd = os.dup(current_fd)
            try:
                with os.scandir(scan_fd) as iterator:
                    children: list[tuple[bytes, os.DirEntry[str]]] = []
                    for child in iterator:
                        try:
                            raw_name = child.name.encode("utf-8", "strict")
                        except UnicodeEncodeError as exc:
                            raise _fail(
                                STATE3_NAMESPACE_PATH_INVALID,
                                f"{label} tree path is not strict UTF-8",
                            ) from exc
                        children.append((raw_name, child))
            finally:
                os.close(scan_fd)
            for _, child in sorted(children, key=lambda item: item[0]):
                entry_count += 1
                if entry_count > max_entries:
                    raise _fail(
                        STATE3_NAMESPACE_LIMIT_EXCEEDED,
                        f"{label} tree exceeds the entry limit",
                    )
                child_components = components + (child.name,)
                relative_path = "/".join(child_components)
                try:
                    raw_path = relative_path.encode("utf-8", "strict")
                except UnicodeEncodeError as exc:
                    raise _fail(
                        STATE3_NAMESPACE_PATH_INVALID,
                        f"{label} tree path is not strict UTF-8",
                    ) from exc
                if len(raw_path) > max_path_bytes:
                    raise _fail(
                        STATE3_NAMESPACE_LIMIT_EXCEEDED,
                        f"{label} tree path exceeds the byte limit",
                    )
                child_stat = os.stat(child.name, dir_fd=current_fd, follow_symlinks=False)
                if stat.S_ISDIR(child_stat.st_mode):
                    child_fd = os.open(child.name, _directory_flags(), dir_fd=current_fd)
                    try:
                        _same_stat(child_stat, os.fstat(child_fd), relative_path)
                        _require_readonly_mount(child_fd, f"{label}:{relative_path}")
                    finally:
                        os.close(child_fd)
                    pending.append((child_components, child_stat))
                elif stat.S_ISREG(child_stat.st_mode):
                    flags = os.O_RDONLY | os.O_NOFOLLOW
                    if hasattr(os, "O_NONBLOCK"):
                        flags |= os.O_NONBLOCK
                    if hasattr(os, "O_CLOEXEC"):
                        flags |= os.O_CLOEXEC
                    child_fd = os.open(child.name, flags, dir_fd=current_fd)
                    try:
                        _same_stat(child_stat, os.fstat(child_fd), relative_path)
                        _require_readonly_mount(child_fd, f"{label}:{relative_path}")
                    finally:
                        os.close(child_fd)
                elif stat.S_ISLNK(child_stat.st_mode):
                    # A symlink inode belongs to its already-checked parent
                    # mount. Runtime validation separately checks its target.
                    continue
        except EIRPrebindingError:
            raise
        except OSError as exc:
            raise _fail(
                STATE3_NAMESPACE_IO_ERROR,
                f"cannot verify recursive {label} immutability: {exc}",
            ) from exc
        finally:
            os.close(current_fd)


def _read_regular_file_commitment(
    root_fd: int,
    relative_path: str,
    *,
    max_path_bytes: int,
    max_file_bytes: int,
    read_chunk_bytes: int,
    label: str,
) -> tuple[int, bytes]:
    """Read one regular file with FD-relative no-follow and race checks."""

    components = _path_components(relative_path, max_path_bytes)
    try:
        root_stat = os.fstat(root_fd)
        current_fd = os.dup(root_fd)
    except OSError as exc:
        raise _fail(STATE3_NAMESPACE_ROOT_INVALID, f"{label} root FD is unavailable: {exc}") from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        os.close(current_fd)
        raise _fail(STATE3_NAMESPACE_ROOT_INVALID, f"{label} root FD is not a directory")
    file_fd: int | None = None
    try:
        _same_stat(root_stat, os.fstat(root_fd), label)
        _require_readonly_mount(current_fd, label)
        for component in components[:-1]:
            try:
                expected = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                if not stat.S_ISDIR(expected.st_mode) or stat.S_ISLNK(expected.st_mode):
                    raise _fail(STATE3_NAMESPACE_PATH_INVALID, f"{label} parent is not a directory")
                next_fd = os.open(component, _directory_flags(), dir_fd=current_fd)
            except EIRPrebindingError:
                raise
            except OSError as exc:
                raise _fail(STATE3_NAMESPACE_IO_ERROR, f"cannot traverse {label}: {exc}") from exc
            try:
                _same_stat(expected, os.fstat(next_fd), label)
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
            _require_readonly_mount(current_fd, label)

        name = components[-1]
        try:
            expected = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        except OSError as exc:
            raise _fail(STATE3_NAMESPACE_IO_ERROR, f"cannot stat {label}: {exc}") from exc
        if not stat.S_ISREG(expected.st_mode) or stat.S_ISLNK(expected.st_mode):
            raise _fail(STATE3_NAMESPACE_PATH_INVALID, f"{label} is not a regular file")
        if expected.st_size > max_file_bytes:
            raise _fail(STATE3_NAMESPACE_FILE_TOO_LARGE, f"{label} exceeds the byte limit")
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            file_fd = os.open(name, flags, dir_fd=current_fd)
        except OSError as exc:
            raise _fail(STATE3_NAMESPACE_IO_ERROR, f"cannot open {label}: {exc}") from exc
        _same_stat(expected, os.fstat(file_fd), label)
        _require_readonly_mount(file_fd, label)
        digest = sha256()
        count = 0
        while True:
            remaining = expected.st_size - count
            try:
                chunk = os.read(file_fd, min(read_chunk_bytes, remaining + 1))
            except OSError as exc:
                raise _fail(STATE3_NAMESPACE_IO_ERROR, f"cannot read {label}: {exc}") from exc
            if not chunk:
                break
            count += len(chunk)
            if count > expected.st_size:
                raise _fail(STATE3_NAMESPACE_RACE_DETECTED, f"{label} grew while reading")
            digest.update(chunk)
        if count != expected.st_size:
            raise _fail(STATE3_NAMESPACE_RACE_DETECTED, f"{label} length changed while reading")
        _same_stat(expected, os.fstat(file_fd), label)
        try:
            after = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        except OSError as exc:
            raise _fail(STATE3_NAMESPACE_RACE_DETECTED, f"{label} disappeared") from exc
        _same_stat(expected, after, label)
        _same_stat(root_stat, os.fstat(root_fd), label)
        return count, digest.digest()
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(current_fd)


def _source_relative_path(virtual_path: str) -> str:
    prefix = "/v631302/src/"
    if not virtual_path.startswith(prefix):
        raise _fail(STATE3_NAMESPACE_PATH_INVALID, "source input lies outside /v631302/src")
    return virtual_path[len(prefix) :]


def _runtime_relative_path(virtual_path: str) -> str:
    if not virtual_path.startswith("/") or virtual_path == "/":
        raise _fail(STATE3_NAMESPACE_PATH_INVALID, "runtime input path is not absolute")
    return virtual_path[1:]


def _bind_tu_observation_to_namespace_open(
    extractor_stdout: bytes,
    *,
    source_root_fd: int,
    runtime_root_fd: int,
    expected_source_root: bytes,
    expected_target_root: bytes = FIXED_TARGET_ROOT,
    expected_toolchain_runtime_root: bytes,
    expected_compiler_binary_sha256: bytes,
    expected_extractor_binary_sha256: bytes,
    expected_compiler_semantics_root: bytes,
    toolchain_runtime_manifest: Any,
    compiler_semantics_manifest: Any,
    executor_effective_frontend_state: Any,
    executor_predefines_bytes: bytes,
    executor_virtual_input_observations: Any,
    source_limits: SourceTreeLimits = DEFAULT_SOURCE_TREE_LIMITS,
    runtime_limits: RuntimeBundleLimits = DEFAULT_RUNTIME_LIMITS,
) -> BoundTUObservation:
    """Bind one validated observation to physical source/runtime bytes.

    The three ``executor_*`` arguments are comparison inputs for a future
    trusted executor. This primitive cannot prove their provenance and always
    leaves ``compiler_recomputed`` and every authority field false.
    """

    source_limits.validate()
    runtime_limits.validate()
    source_root = _bstr32(expected_source_root, "expected_source_root")
    target_root = _bstr32(expected_target_root, "expected_target_root")
    expected_runtime_root = _bstr32(
        expected_toolchain_runtime_root, "expected_toolchain_runtime_root"
    )
    expected_compiler = _bstr32(
        expected_compiler_binary_sha256, "expected_compiler_binary_sha256"
    )
    expected_extractor = _bstr32(
        expected_extractor_binary_sha256, "expected_extractor_binary_sha256"
    )
    expected_semantics = _bstr32(
        expected_compiler_semantics_root, "expected_compiler_semantics_root"
    )

    # Tree-root rechecks cannot exclude an A->B->A race. State3 therefore
    # accepts physical observations only from supervisor-provided read-only
    # mounts; writable host fixtures fail before any observation is bound.
    _require_readonly_mount(source_root_fd, "source")
    _require_readonly_mount(runtime_root_fd, "runtime")
    _verify_readonly_tree(
        source_root_fd,
        "source",
        max_entries=source_limits.max_entries,
        max_path_bytes=source_limits.max_path_bytes,
    )
    _verify_readonly_tree(
        runtime_root_fd,
        "runtime",
        max_entries=runtime_limits.max_entries,
        max_path_bytes=runtime_limits.max_path_bytes,
    )
    source_tree_sha256_fd(source_root_fd, expected_root=source_root, limits=source_limits)
    runtime = validate_toolchain_runtime_manifest(toolchain_runtime_manifest)
    runtime_root = toolchain_runtime_root(runtime)
    if runtime_root != expected_runtime_root:
        raise _fail(STATE3_RUNTIME_ROOT_MISMATCH, "runtime manifest root differs from the trusted value")
    runtime_report = assert_toolchain_runtime_bundle_fd(
        runtime_root_fd, runtime, limits=runtime_limits
    )
    if runtime_report.runtime_root != expected_runtime_root:
        raise _fail(STATE3_RUNTIME_ROOT_MISMATCH, "runtime bytes differ from the trusted root")

    semantics = validate_compiler_semantics_manifest(
        compiler_semantics_manifest,
        runtime_manifest=runtime,
        expected_source_root=source_root,
    )
    semantics_root = compiler_semantics_root(semantics)
    if semantics_root != expected_semantics:
        raise _fail(
            STATE3_COMPILER_SEMANTICS_ROOT_MISMATCH,
            "compiler semantics manifest differs from the trusted root",
        )
    executable_rows = semantics[7][5]
    if executable_rows[0][2] != expected_compiler or executable_rows[1][2] != expected_extractor:
        raise _fail(
            STATE3_EXECUTABLE_DIGEST_MISMATCH,
            "compiler or extractor digest differs from the trusted value",
        )

    raw_stdout = _bstr(extractor_stdout, "extractor_stdout")
    observation = decode_extractor_tu_observation_v2_bytes(raw_stdout)
    tu_ordinal = observation[2]
    units = [unit for unit in semantics[8] if unit[0] == tu_ordinal]
    if len(units) != 1 or units[0][1] != observation[3]:
        raise _fail(STATE3_TU_MANIFEST_MISMATCH, "observation is not the bound translation unit")
    unit = units[0]

    executor_frontend = validate_effective_frontend_state(executor_effective_frontend_state)
    if observation[4] != executor_frontend:
        raise _fail(
            STATE3_EFFECTIVE_FRONTEND_MISMATCH,
            "extractor and executor effective frontend states differ",
        )
    executor_predefines = _bstr(executor_predefines_bytes, "executor_predefines_bytes")
    if observation[7] != executor_predefines:
        raise _fail(STATE3_PREDEFINES_MISMATCH, "extractor and executor predefines differ")
    if eir_canonical_cbor_encode(observation[8]) != eir_canonical_cbor_encode(
        executor_virtual_input_observations
    ):
        raise _fail(
            STATE3_VIRTUAL_INPUT_MISMATCH,
            "extractor and executor virtual input observations differ",
        )

    runtime_entries = {entry[0]: entry for entry in runtime[4]}
    physical_sizes: dict[str, int] = {}

    def read_physical(origin: int, virtual_path: str) -> tuple[int, bytes]:
        if origin == SOURCE_ORIGIN:
            length, digest = _read_regular_file_commitment(
                source_root_fd,
                _source_relative_path(virtual_path),
                max_path_bytes=source_limits.max_path_bytes,
                max_file_bytes=source_limits.max_file_bytes,
                read_chunk_bytes=source_limits.read_chunk_bytes,
                label=virtual_path,
            )
        elif origin == RUNTIME_ORIGIN:
            entry = runtime_entries.get(virtual_path)
            if entry is None or entry[1] != _RUNTIME_REGULAR_FILE:
                raise _fail(
                    STATE3_RUNTIME_INPUT_UNMANIFESTED,
                    f"runtime input is not a manifested regular file: {virtual_path}",
                )
            length, digest = _read_regular_file_commitment(
                runtime_root_fd,
                _runtime_relative_path(virtual_path),
                max_path_bytes=runtime_limits.max_path_bytes,
                max_file_bytes=runtime_limits.max_file_bytes,
                read_chunk_bytes=runtime_limits.read_chunk_bytes,
                label=virtual_path,
            )
            if length != entry[3] or digest != entry[4]:
                raise _fail(
                    STATE3_RUNTIME_INPUT_MISMATCH,
                    f"runtime input differs from its manifest: {virtual_path}",
                )
        else:
            raise _fail(STATE3_NAMESPACE_PATH_INVALID, "physical input origin is invalid")
        physical_sizes[virtual_path] = length
        return length, digest

    primary = observation[5]
    primary_length, primary_digest = read_physical(primary[0], primary[1])
    primary_commitment = [
        primary[0],
        primary[1],
        primary_length,
        primary_digest,
        primary[2],
    ]
    dependency_commitments: list[list[Any]] = []
    for dependency in observation[6]:
        length, digest = read_physical(dependency[1], dependency[2])
        dependency_commitments.append(
            [
                dependency[0],
                dependency[1],
                dependency[2],
                length,
                digest,
                dependency[3],
            ]
        )

    for definition in observation[9]:
        path = definition[6]
        file_size = physical_sizes.get(path)
        if file_size is None or definition[8] > file_size:
            raise _fail(
                STATE3_DEFINITION_SPAN_UNBOUND,
                f"definition span is not contained in an observed source input: {path}",
            )

    predefines_commitment = [len(executor_predefines), sha256(executor_predefines).digest()]
    virtual_commitments: list[list[Any]] = []
    for virtual in observation[8]:
        content = virtual[3]
        virtual_commitments.append(
            [virtual[0], virtual[1], virtual[2], len(content), sha256(content).digest(), virtual[4]]
        )

    content_root = tu_content_root(
        source_root=source_root,
        toolchain_runtime_root=runtime_root,
        tu_ordinal=tu_ordinal,
        primary_input_commitment=primary_commitment,
        dependency_commitments=dependency_commitments,
        predefines_commitment=predefines_commitment,
        virtual_input_commitments=virtual_commitments,
    )
    semantics_root_value = tu_semantics_root(
        source_root=source_root,
        toolchain_runtime_root=runtime_root,
        compiler_binary_sha256=expected_compiler,
        extractor_binary_sha256=expected_extractor,
        compiler_semantics_root=semantics_root,
        tu_ordinal=tu_ordinal,
        primary_source_virtual_path=observation[3],
        working_directory=semantics[3],
        source_mount=semantics[4],
        toolchain_mount=semantics[5],
        environment=semantics[6],
        compiler_command=unit[2],
        extractor_command=unit[3],
        effective_frontend_state=executor_frontend,
    )
    scope = linkage_scope_id(
        source_root=source_root,
        target_root=target_root,
        tu_ordinal=tu_ordinal,
        primary_source_virtual_path=observation[3],
        tu_content_root=content_root,
        tu_semantics_root=semantics_root_value,
    )

    # Re-run complete tree verification after per-file commitments to catch
    # ordinary post-verification mutation. A hostile filesystem still requires
    # the future sealed read-only executor mount described by the binding.
    source_tree_sha256_fd(source_root_fd, expected_root=source_root, limits=source_limits)
    final_runtime_report = assert_toolchain_runtime_bundle_fd(
        runtime_root_fd, runtime, limits=runtime_limits
    )
    if final_runtime_report.runtime_root != expected_runtime_root:
        raise _fail(STATE3_RUNTIME_ROOT_MISMATCH, "runtime changed during TU binding")
    _verify_readonly_tree(
        source_root_fd,
        "source",
        max_entries=source_limits.max_entries,
        max_path_bytes=source_limits.max_path_bytes,
    )
    _verify_readonly_tree(
        runtime_root_fd,
        "runtime",
        max_entries=runtime_limits.max_entries,
        max_path_bytes=runtime_limits.max_path_bytes,
    )

    return BoundTUObservation(
        tu_ordinal=tu_ordinal,
        primary_source_virtual_path=observation[3],
        observation_cbor=raw_stdout,
        primary_input_commitment=tuple(primary_commitment),
        dependency_commitments=tuple(tuple(row) for row in dependency_commitments),
        predefines_commitment=tuple(predefines_commitment),
        virtual_input_commitments=tuple(tuple(row) for row in virtual_commitments),
        definition_instance_observations_cbor=eir_canonical_cbor_encode(observation[9]),
        tu_content_root=content_root,
        tu_semantics_root=semantics_root_value,
        linkage_scope_id=scope,
    )


def bind_tu_observation_to_namespace(
    extractor_stdout: bytes,
    *,
    source_rootfs: os.PathLike[str] | str,
    runtime_rootfs: os.PathLike[str] | str,
    expected_source_root: bytes,
    expected_target_root: bytes = FIXED_TARGET_ROOT,
    expected_toolchain_runtime_root: bytes,
    expected_compiler_binary_sha256: bytes,
    expected_extractor_binary_sha256: bytes,
    expected_compiler_semantics_root: bytes,
    toolchain_runtime_manifest: Any,
    compiler_semantics_manifest: Any,
    executor_effective_frontend_state: Any,
    executor_predefines_bytes: bytes,
    executor_virtual_input_observations: Any,
    source_limits: SourceTreeLimits = DEFAULT_SOURCE_TREE_LIMITS,
    runtime_limits: RuntimeBundleLimits = DEFAULT_RUNTIME_LIMITS,
) -> BoundTUObservation:
    """Bind through roots opened once and retained for every namespace read."""

    with ExitStack() as stack:
        source_root_fd = _open_namespace_root(source_rootfs, "source")
        stack.callback(os.close, source_root_fd)
        runtime_root_fd = _open_namespace_root(runtime_rootfs, "runtime")
        stack.callback(os.close, runtime_root_fd)
        return _bind_tu_observation_to_namespace_open(
            extractor_stdout,
            source_root_fd=source_root_fd,
            runtime_root_fd=runtime_root_fd,
            expected_source_root=expected_source_root,
            expected_target_root=expected_target_root,
            expected_toolchain_runtime_root=expected_toolchain_runtime_root,
            expected_compiler_binary_sha256=expected_compiler_binary_sha256,
            expected_extractor_binary_sha256=expected_extractor_binary_sha256,
            expected_compiler_semantics_root=expected_compiler_semantics_root,
            toolchain_runtime_manifest=toolchain_runtime_manifest,
            compiler_semantics_manifest=compiler_semantics_manifest,
            executor_effective_frontend_state=executor_effective_frontend_state,
            executor_predefines_bytes=executor_predefines_bytes,
            executor_virtual_input_observations=executor_virtual_input_observations,
            source_limits=source_limits,
            runtime_limits=runtime_limits,
        )


__all__ = [
    "BoundTUObservation",
    "STATE3_DEFINITION_SPAN_UNBOUND",
    "STATE3_EFFECTIVE_FRONTEND_MISMATCH",
    "STATE3_NAMESPACE_IMMUTABILITY_UNAVAILABLE",
    "STATE3_PREDEFINES_MISMATCH",
    "STATE3_RUNTIME_INPUT_UNMANIFESTED",
    "STATE3_RUNTIME_INPUT_MISMATCH",
    "STATE3_RUNTIME_ROOT_MISMATCH",
    "STATE3_VIRTUAL_INPUT_MISMATCH",
    "bind_tu_observation_to_namespace",
]
