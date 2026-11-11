"""Exact, zero-authority primitives for protocol-631302 State-3 execution.

The formulas in this module are frozen by
``V631302_TU_SCOPE_AND_STATE3_PROFILE_BINDING_2`` and
``V631302_DEFINITION_OBSERVATION_WIRE_AND_REDUCTION_BINDING_3``. They validate
and hash source bytes, trusted-profile values, per-translation-unit inputs, and
the exact nested observation/reduction wire shapes. They do not run Clang,
establish a trusted OCI deployment, prove global target/ODR closure, accept
observations as evidence, or advance a prebinding to ``COMPILER_RECOMPUTED``.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Sequence

from .eir_prebinding import (
    AGENT_MODIFICATION_AUTHORITY,
    AUTHORITY,
    PREBINDING_ROOT_MISMATCH,
    ENGINE_WIRING_AUTHORITY,
    ENVIRONMENT,
    EIRPrebindingError,
    HOLDOUT_ACCESS_AUTHORITY,
    HELPER_REF,
    INVOCATION_KINDS,
    LINKAGE_ODR_MERGEABLE,
    LINKAGE_TRANSLATION_UNIT_LOCAL,
    PERMIT_AUTHORITY,
    PROTOCOL_ID,
    RESOLUTION_EXACT_FINITE_SET,
    RESOLUTION_EXACT_SINGLE,
    TARGET_REF,
    TERMINAL_REF,
    UPLOAD_AUTHORITY,
    ZERO32,
    backend_matcher_root as compute_backend_matcher_root,
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
    external_terminal_root as compute_external_terminal_root,
    qtid_ascii_v1,
    validate_backend_matcher_registry,
    validate_external_terminal_registry,
    validate_declaration_key,
)


STATE3_PROFILE_INVALID = "STATE3_PROFILE_INVALID"
STATE3_PROFILE_ID_MISMATCH = "STATE3_PROFILE_ID_MISMATCH"
STATE3_TRUST_ALLOWLIST_INVALID = "STATE3_TRUST_ALLOWLIST_INVALID"
STATE3_TRUST_ALLOWLIST_DUPLICATE_PROFILE = "STATE3_TRUST_ALLOWLIST_DUPLICATE_PROFILE"
STATE3_TRUST_ALLOWLIST_CONFLICT = "STATE3_TRUST_ALLOWLIST_CONFLICT"

SOURCE_TREE_SYMLINK_FORBIDDEN = "SOURCE_TREE_SYMLINK_FORBIDDEN"
SOURCE_TREE_NONREGULAR_ENTRY = "SOURCE_TREE_NONREGULAR_ENTRY"
SOURCE_TREE_DUPLICATE_PATH = "SOURCE_TREE_DUPLICATE_PATH"
SOURCE_TREE_PATH_INVALID = "SOURCE_TREE_PATH_INVALID"
SOURCE_TREE_PATH_TOO_LONG = "SOURCE_TREE_PATH_TOO_LONG"
SOURCE_FILE_TOO_LARGE = "SOURCE_FILE_TOO_LARGE"
SOURCE_TREE_LIMIT_EXCEEDED = "SOURCE_TREE_LIMIT_EXCEEDED"
SOURCE_TREE_RACE_DETECTED = "SOURCE_TREE_RACE_DETECTED"
SOURCE_TREE_IO_ERROR = "SOURCE_TREE_IO_ERROR"
SOURCE_ROOT_MISMATCH = "SOURCE_ROOT_MISMATCH"

TU_PRIMARY_INPUT_INVALID = "TU_PRIMARY_INPUT_INVALID"
TU_DEPENDENCY_ORIGIN_INVALID = "TU_DEPENDENCY_ORIGIN_INVALID"
TU_DEPENDENCY_PATH_INVALID = "TU_DEPENDENCY_PATH_INVALID"
TU_DEPENDENCY_DUPLICATE = "TU_DEPENDENCY_DUPLICATE"
TU_DEPENDENCY_ORDER_INVALID = "TU_DEPENDENCY_ORDER_INVALID"
TU_VIRTUAL_INPUT_INVALID = "TU_VIRTUAL_INPUT_INVALID"
TU_VIRTUAL_INPUT_ORDER_INVALID = "TU_VIRTUAL_INPUT_ORDER_INVALID"
TU_PREDEFINES_MISSING = "TU_PREDEFINES_MISSING"
WORK_SEMANTIC_INPUT_FORBIDDEN = "WORK_SEMANTIC_INPUT_FORBIDDEN"
EXTRACTOR_INPUT_CLOSURE_INCOMPLETE = "EXTRACTOR_INPUT_CLOSURE_INCOMPLETE"

EXTRACTOR_OBSERVATION_VERSION_UNSUPPORTED = "EXTRACTOR_OBSERVATION_VERSION_UNSUPPORTED"
EFFECTIVE_CC1_COMMAND_INVALID = "EFFECTIVE_CC1_COMMAND_INVALID"
UNSUPPORTED_FRONTEND_ACTION_COUNT = "UNSUPPORTED_FRONTEND_ACTION_COUNT"
EFFECTIVE_TARGET_TRIPLE_INVALID = "EFFECTIVE_TARGET_TRIPLE_INVALID"
EFFECTIVE_LANGUAGE_MODE_INVALID = "EFFECTIVE_LANGUAGE_MODE_INVALID"
EFFECTIVE_RESOURCE_PATH_INVALID = "EFFECTIVE_RESOURCE_PATH_INVALID"
UNSUPPORTED_IMPLICIT_COMPILER_STATE = "UNSUPPORTED_IMPLICIT_COMPILER_STATE"
HOST_DEPENDENT_COMPILER_OPTION_FORBIDDEN = "HOST_DEPENDENT_COMPILER_OPTION_FORBIDDEN"
TU_SCOPE_EVIDENCE_INCOMPLETE = "TU_SCOPE_EVIDENCE_INCOMPLETE"
STATE3_DEFINITION_OBSERVATION_CONTRACT_UNAVAILABLE = (
    "STATE3_DEFINITION_OBSERVATION_CONTRACT_UNAVAILABLE"
)
DEFINITION_AST_ROOT_MISSING = "DEFINITION_AST_ROOT_MISSING"
DEFINITION_AST_ROOT_AMBIGUOUS = "DEFINITION_AST_ROOT_AMBIGUOUS"
AST_ANCHOR_PATH_INVALID = "AST_ANCHOR_PATH_INVALID"
AST_ANCHOR_CHILD_COUNT_OVERFLOW = "AST_ANCHOR_CHILD_COUNT_OVERFLOW"
INVOCATION_ANCHOR_UNAVAILABLE = "INVOCATION_ANCHOR_UNAVAILABLE"
DEFINITION_DECL_KIND_UNSUPPORTED = "DEFINITION_DECL_KIND_UNSUPPORTED"
CALLEE_DECL_KIND_UNSUPPORTED = "CALLEE_DECL_KIND_UNSUPPORTED"
LINKAGE_CLASS_UNSUPPORTED = "LINKAGE_CLASS_UNSUPPORTED"
INVOCATION_KIND_INVALID = "INVOCATION_KIND_INVALID"
RESOLUTION_KIND_INVALID = "RESOLUTION_KIND_INVALID"
CALLEE_ORIGIN_INVALID = "CALLEE_ORIGIN_INVALID"
INVOCATION_OCCURRENCE_SCHEMA_INVALID = "INVOCATION_OCCURRENCE_SCHEMA_INVALID"
INVOCATION_OCCURRENCE_ORDINAL_INVALID = "INVOCATION_OCCURRENCE_ORDINAL_INVALID"
INVOCATION_OCCURRENCE_ORDER_INVALID = "INVOCATION_OCCURRENCE_ORDER_INVALID"
CALLEE_DESCRIPTOR_SCHEMA_INVALID = "CALLEE_DESCRIPTOR_SCHEMA_INVALID"
CALLEE_DESCRIPTOR_ORDER_INVALID = "CALLEE_DESCRIPTOR_ORDER_INVALID"
CALLEE_DESCRIPTOR_DUPLICATE = "CALLEE_DESCRIPTOR_DUPLICATE"
CALLEE_DESCRIPTOR_IDENTITY_COLLISION = "CALLEE_DESCRIPTOR_IDENTITY_COLLISION"
CALLEE_RESOLUTION_CARDINALITY_INVALID = "CALLEE_RESOLUTION_CARDINALITY_INVALID"
TARGET_INDEX_OUT_OF_RANGE = "TARGET_INDEX_OUT_OF_RANGE"
TARGET_INDEX_ORDER_INVALID = "TARGET_INDEX_ORDER_INVALID"
TARGET_INDEX_DUPLICATE = "TARGET_INDEX_DUPLICATE"
TARGET_INDEX_MULTIPLE_DEFINITIONS_IN_TU = "TARGET_INDEX_MULTIPLE_DEFINITIONS_IN_TU"
TARGET_INDEX_SET_INCOMPLETE = "TARGET_INDEX_SET_INCOMPLETE"
TARGET_INDEX_ODR_DRIFT = "TARGET_INDEX_ODR_DRIFT"
TARGET_ALIAS_IDENTITY_MISMATCH = "TARGET_ALIAS_IDENTITY_MISMATCH"
DEFINITION_COVERAGE_COUNT_MISMATCH = "DEFINITION_COVERAGE_COUNT_MISMATCH"
INVOCATION_COVERAGE_ACCOUNTING_MISMATCH = "INVOCATION_COVERAGE_ACCOUNTING_MISMATCH"
EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE = "EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE"
EXTRACTOR_INVOCATION_CLOSURE_INCOMPLETE = "EXTRACTOR_INVOCATION_CLOSURE_INCOMPLETE"
CALLEE_SOURCE_DEFINITION_NOT_FOUND = "CALLEE_SOURCE_DEFINITION_NOT_FOUND"
CALLEE_SOURCE_DEFINITION_AMBIGUOUS = "CALLEE_SOURCE_DEFINITION_AMBIGUOUS"
CALLEE_TERMINAL_CONTEXT_REQUIRED = "CALLEE_TERMINAL_CONTEXT_REQUIRED"
CALLEE_TERMINAL_NOT_FOUND = "CALLEE_TERMINAL_NOT_FOUND"
CALLEE_TERMINAL_AMBIGUOUS = "CALLEE_TERMINAL_AMBIGUOUS"
CALLEE_BUILTIN_TERMINAL_MISMATCH = "CALLEE_BUILTIN_TERMINAL_MISMATCH"
CALLEE_REF_ALIAS_COLLISION = "CALLEE_REF_ALIAS_COLLISION"
INVOCATION_OCCURRENCE_COUNT_OVERFLOW = "INVOCATION_OCCURRENCE_COUNT_OVERFLOW"
INVOCATION_REDUCTION_MISMATCH = "INVOCATION_REDUCTION_MISMATCH"

DS_STATE3_EXECUTION_PROFILE = b"V631302/STATE3_EXECUTION_PROFILE\x00"
DS_STATE3_LOCAL_TRUST_ALLOWLIST_ROOT = b"V631302/STATE3_LOCAL_TRUST_ALLOWLIST_ROOT\x00"
DS_TU_CONTENT_ROOT = b"V631302/TU_CONTENT_ROOT\x00"
DS_TU_SEMANTICS_ROOT = b"V631302/TU_SEMANTICS_ROOT\x00"
DS_LINKAGE_SCOPE_ID = b"V631302/LINKAGE_SCOPE_ID\x00"

STATE3_PROFILE_VERSION = 1
STATE3_PREBINDING_WIRE_VERSION = 2
STATE3_ALLOWLIST_VERSION = 1
TU_CONTENT_VERSION = 1
TU_SEMANTICS_VERSION = 1
EXTRACTOR_OBSERVATION_VERSION = 2
SOURCE_ORIGIN = 1
RUNTIME_ORIGIN = 2
LANGUAGE_CXX = 2
VIRTUAL_INPUT_KINDS = frozenset((1, 2, 3))
PINNED_STATE3_LOCAL_TRUST_ALLOWLIST_ROOT: bytes | None = None

CALIBRATION_UPLOAD_AUTHORITY = False
PRODUCTION_UPLOAD_AUTHORITY = False
SEALED_HOLDOUT_ACCESS_AUTHORITY = False
COMPILER_RECOMPUTED = False
EXTERNAL_EVIDENCE_VALID = False
EIR_FREEZE_AUTHORITY = False

_UINT_LIMITS = {8: 1 << 8, 16: 1 << 16, 32: 1 << 32, 64: 1 << 64}
_FORBIDDEN_NATIVE_OPTIONS = ("-march=native", "-mcpu=native", "-mtune=native")
_CALLABLE_DECL_KINDS = frozenset(
    (
        "FunctionDecl",
        "CXXMethodDecl",
        "CXXConstructorDecl",
        "CXXDestructorDecl",
        "CXXConversionDecl",
    )
)
_CALLEE_ORIGINS = frozenset((1, 2, 3))
_RESERVED_PHYSICAL_PREFIXES = (
    "/dev",
    "/proc",
    "/sys",
    "/v631302/input",
    "/v631302/work",
)


@dataclass(frozen=True)
class SourceTreeLimits:
    max_entries: int = 250_000
    max_path_bytes: int = 4096
    max_file_bytes: int = 1 << 34
    max_total_file_bytes: int = 1 << 40
    read_chunk_bytes: int = 1 << 20

    def validate(self) -> None:
        values = (
            self.max_entries,
            self.max_path_bytes,
            self.max_file_bytes,
            self.max_total_file_bytes,
            self.read_chunk_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("source-tree limits must be positive integers")
        if self.max_file_bytes > self.max_total_file_bytes:
            raise ValueError("max_file_bytes cannot exceed max_total_file_bytes")


DEFAULT_SOURCE_TREE_LIMITS = SourceTreeLimits()


def _fail(code: str, message: str) -> EIRPrebindingError:
    return EIRPrebindingError(code, message)


def _array(value: Any, label: str) -> Sequence[Any]:
    if type(value) not in (list, tuple):
        raise _fail(STATE3_PROFILE_INVALID, f"{label} must be a CBOR array")
    return value


def _uint(value: Any, bits: int, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value >= _UINT_LIMITS[bits]:
        raise _fail(STATE3_PROFILE_INVALID, f"{label} must fit uint{bits}")
    if positive and value == 0:
        raise _fail(STATE3_PROFILE_INVALID, f"{label} must be positive")
    return value


def _bstr(value: Any, label: str) -> bytes:
    if type(value) is not bytes:
        raise _fail(STATE3_PROFILE_INVALID, f"{label} must be a byte string")
    return value


def _bstr32(value: Any, label: str) -> bytes:
    result = _bstr(value, label)
    if len(result) != 32:
        raise _fail(STATE3_PROFILE_INVALID, f"{label} must be exactly 32 bytes")
    return result


def _text(value: Any, label: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value) or "\x00" in value:
        raise _fail(STATE3_PROFILE_INVALID, f"{label} must be valid NUL-free text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(STATE3_PROFILE_INVALID, f"{label} is not valid UTF-8") from exc
    return value


def _canonical_path(value: Any, label: str, *, allow_empty: bool = False) -> str:
    path = _text(value, label, nonempty=not allow_empty)
    if allow_empty and not path:
        return path
    if not path.startswith("/") or (path != "/" and path.endswith("/")):
        raise _fail(STATE3_PROFILE_INVALID, f"{label} is not an absolute canonical POSIX path")
    components = [] if path == "/" else path[1:].split("/")
    if any(component in ("", ".", "..") for component in components):
        raise _fail(STATE3_PROFILE_INVALID, f"{label} contains an invalid path component")
    return path


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _hash(domain: bytes, value: Any) -> bytes:
    return sha256(domain + eir_canonical_cbor_encode(value)).digest()


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise _fail(SOURCE_TREE_IO_ERROR, "safe no-follow directory opens are unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


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
        raise _fail(SOURCE_TREE_RACE_DETECTED, f"source object changed while reading {label}")


def _source_component(name: str, limits: SourceTreeLimits) -> bytes:
    if type(name) is not str or not name or name in (".", "..") or "/" in name or "\x00" in name:
        raise _fail(SOURCE_TREE_PATH_INVALID, "source path contains an invalid component")
    try:
        raw = name.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(SOURCE_TREE_PATH_INVALID, "source path is not strict UTF-8") from exc
    if len(raw) > limits.max_path_bytes:
        raise _fail(SOURCE_TREE_PATH_TOO_LONG, "source path exceeds the configured limit")
    return raw


def _read_source_file(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    relative_path: str,
    limits: SourceTreeLimits,
    total: list[int],
    digest: Any,
    path_bytes: bytes,
) -> bytes:
    if expected.st_size > limits.max_file_bytes:
        raise _fail(SOURCE_FILE_TOO_LARGE, f"source file exceeds the per-file limit: {relative_path}")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise _fail(SOURCE_TREE_IO_ERROR, f"cannot open source file {relative_path}: {exc}") from exc
    count = 0
    content_digest = sha256()
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise _fail(SOURCE_TREE_RACE_DETECTED, f"source entry changed type: {relative_path}")
        _same_stat(expected, opened, relative_path)
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(expected.st_size.to_bytes(8, "big"))
        while True:
            remaining_file = limits.max_file_bytes - count
            remaining_total = limits.max_total_file_bytes - total[0] - count
            if remaining_file < 0 or remaining_total < 0:
                raise _fail(SOURCE_FILE_TOO_LARGE, f"source byte budget exhausted: {relative_path}")
            request = min(limits.read_chunk_bytes, remaining_file + 1, remaining_total + 1)
            chunk = os.read(fd, request)
            if not chunk:
                break
            if len(chunk) > remaining_file or len(chunk) > remaining_total:
                raise _fail(SOURCE_FILE_TOO_LARGE, f"source file grew past a byte limit: {relative_path}")
            digest.update(chunk)
            content_digest.update(chunk)
            count += len(chunk)
        _same_stat(opened, os.fstat(fd), relative_path)
    except OSError as exc:
        raise _fail(SOURCE_TREE_IO_ERROR, f"cannot read source file {relative_path}: {exc}") from exc
    finally:
        os.close(fd)
    try:
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise _fail(SOURCE_TREE_RACE_DETECTED, f"source file disappeared: {relative_path}") from exc
    _same_stat(expected, after, relative_path)
    if count != expected.st_size:
        raise _fail(SOURCE_TREE_RACE_DETECTED, f"source file length changed: {relative_path}")
    total[0] += count
    return content_digest.digest()


def _walk_source_directory(
    directory_fd: int,
    relative_components: tuple[str, ...],
    limits: SourceTreeLimits,
    rows: list[tuple[bytes, tuple[str, ...], os.stat_result]],
    directories: dict[tuple[str, ...], os.stat_result],
    entry_count: list[int],
    expected_total: list[int],
) -> None:
    before = os.fstat(directory_fd)
    scan_fd = os.dup(directory_fd)
    children: list[tuple[bytes, str, os.stat_result]] = []
    try:
        with os.scandir(scan_fd) as iterator:
            for child in iterator:
                entry_count[0] += 1
                if entry_count[0] > limits.max_entries:
                    raise _fail(SOURCE_TREE_LIMIT_EXCEEDED, "source tree exceeds the entry limit")
                raw_name = _source_component(child.name, limits)
                try:
                    child_stat = os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as exc:
                    raise _fail(SOURCE_TREE_RACE_DETECTED, f"source entry changed: {child.name}") from exc
                children.append((raw_name, child.name, child_stat))
    except EIRPrebindingError:
        raise
    except OSError as exc:
        raise _fail(SOURCE_TREE_IO_ERROR, f"cannot enumerate source directory: {exc}") from exc
    finally:
        try:
            os.close(scan_fd)
        except OSError:
            pass
    _same_stat(before, os.fstat(directory_fd), "/".join(relative_components) or ".")

    for raw_name, name, child_stat in sorted(children, key=lambda item: item[0]):
        components = relative_components + (name,)
        relative_path = "/".join(components)
        try:
            path_bytes = relative_path.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise _fail(SOURCE_TREE_PATH_INVALID, "source relative path is not strict UTF-8") from exc
        if len(path_bytes) > limits.max_path_bytes:
            raise _fail(SOURCE_TREE_PATH_TOO_LONG, f"source path is too long: {relative_path}")
        mode = child_stat.st_mode
        if stat.S_ISLNK(mode):
            raise _fail(SOURCE_TREE_SYMLINK_FORBIDDEN, f"source symlink is forbidden: {relative_path}")
        if stat.S_ISDIR(mode):
            directories[components] = child_stat
            try:
                child_fd = os.open(name, _directory_flags(), dir_fd=directory_fd)
            except OSError as exc:
                raise _fail(SOURCE_TREE_RACE_DETECTED, f"cannot safely open source directory {relative_path}") from exc
            try:
                _same_stat(child_stat, os.fstat(child_fd), relative_path)
                _walk_source_directory(
                    child_fd,
                    components,
                    limits,
                    rows,
                    directories,
                    entry_count,
                    expected_total,
                )
                _same_stat(child_stat, os.fstat(child_fd), relative_path)
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(mode):
            raise _fail(SOURCE_TREE_NONREGULAR_ENTRY, f"source entry is not regular: {relative_path}")
        if child_stat.st_size > limits.max_file_bytes:
            raise _fail(SOURCE_FILE_TOO_LARGE, f"source file exceeds the per-file limit: {relative_path}")
        expected_total[0] += child_stat.st_size
        if expected_total[0] > limits.max_total_file_bytes:
            raise _fail(SOURCE_TREE_LIMIT_EXCEEDED, "source tree exceeds the aggregate byte limit")
        rows.append((path_bytes, components, child_stat))


def _open_source_directory_chain(
    root_fd: int,
    components: tuple[str, ...],
    directories: dict[tuple[str, ...], os.stat_result],
) -> int:
    current_fd = os.dup(root_fd)
    prefix: tuple[str, ...] = ()
    try:
        for component in components:
            prefix += (component,)
            expected = directories[prefix]
            try:
                next_fd = os.open(component, _directory_flags(), dir_fd=current_fd)
            except OSError as exc:
                raise _fail(
                    SOURCE_TREE_RACE_DETECTED,
                    f"cannot safely reopen source directory {'/'.join(prefix)}",
                ) from exc
            try:
                _same_stat(expected, os.fstat(next_fd), "/".join(prefix))
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _recheck_source_file(
    root_fd: int,
    components: tuple[str, ...],
    expected: os.stat_result,
    expected_content_sha256: bytes,
    directories: dict[tuple[str, ...], os.stat_result],
    limits: SourceTreeLimits,
) -> None:
    relative_path = "/".join(components)
    parent_fd = _open_source_directory_chain(root_fd, components[:-1], directories)
    fd: int | None = None
    try:
        try:
            before = os.stat(components[-1], dir_fd=parent_fd, follow_symlinks=False)
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            fd = os.open(components[-1], flags, dir_fd=parent_fd)
        except OSError as exc:
            raise _fail(
                SOURCE_TREE_RACE_DETECTED,
                f"cannot safely recheck source file {relative_path}",
            ) from exc
        _same_stat(expected, before, relative_path)
        _same_stat(expected, os.fstat(fd), relative_path)
        content_digest = sha256()
        count = 0
        while True:
            remaining = expected.st_size - count
            try:
                chunk = os.read(fd, min(limits.read_chunk_bytes, remaining + 1))
            except OSError as exc:
                raise _fail(
                    SOURCE_TREE_RACE_DETECTED,
                    f"cannot re-read source file {relative_path}",
                ) from exc
            if not chunk:
                break
            count += len(chunk)
            if count > expected.st_size:
                raise _fail(
                    SOURCE_TREE_RACE_DETECTED,
                    f"source file grew during final recheck: {relative_path}",
                )
            content_digest.update(chunk)
        if count != expected.st_size or content_digest.digest() != expected_content_sha256:
            raise _fail(
                SOURCE_TREE_RACE_DETECTED,
                f"source file content changed after hashing: {relative_path}",
            )
        _same_stat(expected, os.fstat(fd), relative_path)
        try:
            after = os.stat(components[-1], dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise _fail(
                SOURCE_TREE_RACE_DETECTED,
                f"source file disappeared during final recheck: {relative_path}",
            ) from exc
        _same_stat(expected, after, relative_path)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def _source_tree_sha256_open_fd(
    root_fd: int,
    *,
    expected_root: bytes | None,
    limits: SourceTreeLimits,
) -> bytes:
    """Hash a source tree through a caller-owned, already-open directory FD."""

    root_stat = os.fstat(root_fd)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise _fail(SOURCE_TREE_NONREGULAR_ENTRY, "source root FD must name a directory")
    rows: list[tuple[bytes, tuple[str, ...], os.stat_result]] = []
    directories: dict[tuple[str, ...], os.stat_result] = {}
    _same_stat(root_stat, os.fstat(root_fd), ".")
    _walk_source_directory(root_fd, (), limits, rows, directories, [0], [0])
    _same_stat(root_stat, os.fstat(root_fd), ".")
    paths = [path for path, _, _ in rows]
    if len(paths) != len(set(paths)):
        raise _fail(SOURCE_TREE_DUPLICATE_PATH, "source tree contains duplicate path bytes")
    digest = sha256()
    actual_total = [0]
    content_digests: dict[bytes, bytes] = {}
    for path_bytes, components, expected in sorted(rows, key=lambda item: item[0]):
        parent_fd = _open_source_directory_chain(root_fd, components[:-1], directories)
        try:
            content_digests[path_bytes] = _read_source_file(
                parent_fd,
                components[-1],
                expected,
                "/".join(components),
                limits,
                actual_total,
                digest,
                path_bytes,
            )
        finally:
            os.close(parent_fd)
    for components in sorted(directories, key=lambda item: "/".join(item).encode("utf-8")):
        directory_fd = _open_source_directory_chain(root_fd, components, directories)
        try:
            _same_stat(directories[components], os.fstat(directory_fd), "/".join(components))
        finally:
            os.close(directory_fd)
    for _, components, expected in sorted(rows, key=lambda item: item[0]):
        path_bytes = "/".join(components).encode("utf-8", "strict")
        _recheck_source_file(
            root_fd,
            components,
            expected,
            content_digests[path_bytes],
            directories,
            limits,
        )
    _same_stat(root_stat, os.fstat(root_fd), ".")
    result = digest.digest()
    if expected_root is not None and result != _bstr32(expected_root, "expected_source_root"):
        raise _fail(SOURCE_ROOT_MISMATCH, "recomputed source root does not match the expected root")
    return result


def source_tree_sha256_fd(
    source_root_fd: int,
    *,
    expected_root: bytes | None = None,
    limits: SourceTreeLimits = DEFAULT_SOURCE_TREE_LIMITS,
) -> bytes:
    """Recompute the source digest beneath one retained directory descriptor."""

    limits.validate()
    try:
        root_fd = os.dup(source_root_fd)
    except (TypeError, ValueError, OSError) as exc:
        raise _fail(SOURCE_TREE_IO_ERROR, f"source root FD is unavailable: {exc}") from exc
    try:
        return _source_tree_sha256_open_fd(
            root_fd,
            expected_root=expected_root,
            limits=limits,
        )
    finally:
        os.close(root_fd)


def source_tree_sha256(
    source_root: os.PathLike[str] | str,
    *,
    expected_root: bytes | None = None,
    limits: SourceTreeLimits = DEFAULT_SOURCE_TREE_LIMITS,
) -> bytes:
    """Recompute the legacy, separator-free source tree digest exactly."""

    limits.validate()
    try:
        root_path = os.path.abspath(os.fspath(source_root))
        root_stat = os.lstat(root_path)
    except (TypeError, ValueError, OSError) as exc:
        raise _fail(SOURCE_TREE_IO_ERROR, f"source root is unavailable: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode):
        raise _fail(SOURCE_TREE_SYMLINK_FORBIDDEN, "source root may not be a symlink")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise _fail(SOURCE_TREE_NONREGULAR_ENTRY, "source root must be a directory")
    try:
        root_fd = os.open(root_path, _directory_flags())
    except OSError as exc:
        raise _fail(SOURCE_TREE_IO_ERROR, f"cannot safely open source root: {exc}") from exc
    try:
        _same_stat(root_stat, os.fstat(root_fd), ".")
        return _source_tree_sha256_open_fd(
            root_fd,
            expected_root=expected_root,
            limits=limits,
        )
    finally:
        os.close(root_fd)


def validate_state3_execution_profile(value: Any) -> list[Any]:
    row = _array(value, "state3_execution_profile")
    if len(row) != 12 or list(row[:3]) != [PROTOCOL_ID, STATE3_PROFILE_VERSION, STATE3_PREBINDING_WIRE_VERSION]:
        raise _fail(STATE3_PROFILE_INVALID, "state-3 execution profile header or width is invalid")
    return [PROTOCOL_ID, STATE3_PROFILE_VERSION, STATE3_PREBINDING_WIRE_VERSION] + [
        _bstr32(item, f"state3_profile_root_{index}") for index, item in enumerate(row[3:], 1)
    ]


def state3_execution_profile_id(value: Any) -> bytes:
    return _hash(DS_STATE3_EXECUTION_PROFILE, validate_state3_execution_profile(value))


def validate_state3_local_trust_allowlist(value: Any) -> list[Any]:
    row = _array(value, "state3_local_trust_allowlist")
    if len(row) != 3 or list(row[:2]) != [PROTOCOL_ID, STATE3_ALLOWLIST_VERSION]:
        raise _fail(STATE3_TRUST_ALLOWLIST_INVALID, "state-3 trust allowlist header is invalid")
    entries: list[list[Any]] = []
    prior_by_id: dict[bytes, list[Any]] = {}
    for item in _array(row[2], "trusted_profile_entries"):
        entry = _array(item, "trusted_profile_entry")
        if len(entry) != 4:
            raise _fail(STATE3_TRUST_ALLOWLIST_INVALID, "trusted profile entry has the wrong width")
        declared_id = _bstr32(entry[0], "state3_profile_id")
        profile = validate_state3_execution_profile(entry[1])
        if state3_execution_profile_id(profile) != declared_id:
            raise _fail(STATE3_PROFILE_ID_MISMATCH, "trusted profile ID does not bind its profile")
        normalized = [
            declared_id,
            profile,
            _bstr32(entry[2], "executor_oci_manifest_sha256"),
            _bstr32(entry[3], "launcher_oci_manifest_sha256"),
        ]
        prior = prior_by_id.get(declared_id)
        if prior is not None:
            code = STATE3_TRUST_ALLOWLIST_DUPLICATE_PROFILE if prior == normalized else STATE3_TRUST_ALLOWLIST_CONFLICT
            raise _fail(code, "state-3 trust allowlist repeats a profile ID")
        prior_by_id[declared_id] = normalized
        entries.append(normalized)
    ids = [entry[0] for entry in entries]
    if ids != sorted(ids):
        raise _fail(STATE3_TRUST_ALLOWLIST_INVALID, "trusted profile entries are not raw-ID sorted")
    return [PROTOCOL_ID, STATE3_ALLOWLIST_VERSION, entries]


def state3_local_trust_allowlist_root(value: Any) -> bytes:
    return _hash(DS_STATE3_LOCAL_TRUST_ALLOWLIST_ROOT, validate_state3_local_trust_allowlist(value))


def _physical_path(origin: int, value: Any, label: str) -> str:
    path = _canonical_path(value, label)
    if _inside(path, "/v631302/work"):
        raise _fail(WORK_SEMANTIC_INPUT_FORBIDDEN, f"{label} lies in the work tree")
    if origin == SOURCE_ORIGIN:
        if not _inside(path, "/v631302/src"):
            raise _fail(TU_DEPENDENCY_PATH_INVALID, f"{label} is outside the source tree")
    elif origin == RUNTIME_ORIGIN:
        if _inside(path, "/v631302/src") or any(_inside(path, prefix) for prefix in _RESERVED_PHYSICAL_PREFIXES):
            raise _fail(TU_DEPENDENCY_PATH_INVALID, f"{label} is outside the runtime namespace")
    else:
        raise _fail(TU_DEPENDENCY_ORIGIN_INVALID, f"{label} has an invalid physical origin")
    return path


def _primary_commitment(value: Any) -> list[Any]:
    row = _array(value, "primary_input_commitment")
    if len(row) != 5 or row[0] != SOURCE_ORIGIN:
        raise _fail(TU_PRIMARY_INPUT_INVALID, "primary input commitment is invalid")
    path = _physical_path(SOURCE_ORIGIN, row[1], "primary input path")
    return [
        SOURCE_ORIGIN,
        path,
        _uint(row[2], 64, "primary input byte length"),
        _bstr32(row[3], "primary input digest"),
        _uint(row[4], 32, "primary activation count", positive=True),
    ]


def _dependency_commitments(value: Any, primary_path: str) -> list[list[Any]]:
    rows: list[list[Any]] = []
    keys: list[tuple[int, bytes]] = []
    for expected_ordinal, item in enumerate(_array(value, "dependency_commitments")):
        row = _array(item, "dependency_commitment")
        if len(row) != 6 or _uint(row[0], 32, "dependency ordinal") != expected_ordinal:
            raise _fail(TU_DEPENDENCY_ORDER_INVALID, "dependency ordinals must be dense")
        origin = _uint(row[1], 8, "dependency origin")
        path = _physical_path(origin, row[2], "dependency path")
        if origin == SOURCE_ORIGIN and path == primary_path:
            raise _fail(TU_DEPENDENCY_DUPLICATE, "primary input is repeated as a dependency")
        normalized = [
            expected_ordinal,
            origin,
            path,
            _uint(row[3], 64, "dependency byte length"),
            _bstr32(row[4], "dependency digest"),
            _uint(row[5], 32, "dependency activation count", positive=True),
        ]
        rows.append(normalized)
        keys.append((origin, path.encode("utf-8")))
    if keys != sorted(keys):
        raise _fail(TU_DEPENDENCY_ORDER_INVALID, "dependencies are not origin/path sorted")
    if len(keys) != len(set(keys)):
        raise _fail(TU_DEPENDENCY_DUPLICATE, "dependency path is duplicated")
    return rows


def _predefines_commitment(value: Any) -> list[Any]:
    row = _array(value, "predefines_commitment")
    if len(row) != 2:
        raise _fail(TU_PREDEFINES_MISSING, "predefines commitment has the wrong width")
    return [_uint(row[0], 64, "predefines byte length"), _bstr32(row[1], "predefines digest")]


def _virtual_commitments(value: Any) -> list[list[Any]]:
    rows: list[list[Any]] = []
    keys: list[bytes] = []
    for expected_ordinal, item in enumerate(_array(value, "virtual_input_commitments")):
        row = _array(item, "virtual_input_commitment")
        if len(row) != 6 or _uint(row[0], 32, "virtual input ordinal") != expected_ordinal:
            raise _fail(TU_VIRTUAL_INPUT_INVALID, "virtual input ordinal is not dense")
        kind = _uint(row[1], 8, "virtual input kind")
        if kind not in VIRTUAL_INPUT_KINDS:
            raise _fail(TU_VIRTUAL_INPUT_INVALID, "virtual input kind is reserved")
        name = _text(row[2], "virtual input logical name")
        length = _uint(row[3], 64, "virtual input byte length")
        digest = _bstr32(row[4], "virtual input digest")
        activation = _uint(row[5], 32, "virtual input activation count", positive=True)
        rows.append([expected_ordinal, kind, name, length, digest, activation])
        keys.append(eir_canonical_cbor_encode([kind, name, length, digest]))
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise _fail(TU_VIRTUAL_INPUT_ORDER_INVALID, "virtual inputs are not unique and canonically sorted")
    return rows


def tu_content_root(
    *,
    source_root: bytes,
    toolchain_runtime_root: bytes,
    tu_ordinal: int,
    primary_input_commitment: Any,
    dependency_commitments: Any,
    predefines_commitment: Any,
    virtual_input_commitments: Any,
) -> bytes:
    primary = _primary_commitment(primary_input_commitment)
    dependencies = _dependency_commitments(dependency_commitments, primary[1])
    predefines = _predefines_commitment(predefines_commitment)
    virtual = _virtual_commitments(virtual_input_commitments)
    value = [
        PROTOCOL_ID,
        TU_CONTENT_VERSION,
        _bstr32(source_root, "source_root"),
        _bstr32(toolchain_runtime_root, "toolchain_runtime_root"),
        _uint(tu_ordinal, 32, "tu_ordinal"),
        primary,
        dependencies,
        predefines,
        virtual,
    ]
    return _hash(DS_TU_CONTENT_ROOT, value)


def _command(value: Any, label: str) -> list[str]:
    command = [_text(item, f"{label} argument") for item in _array(value, label)]
    if not command:
        raise _fail(EFFECTIVE_CC1_COMMAND_INVALID, f"{label} is empty")
    for argument in command:
        if "@" in argument or argument == "-":
            raise _fail(EFFECTIVE_CC1_COMMAND_INVALID, f"{label} contains a forbidden input form")
        if any(argument == option or argument.startswith(option + "=") for option in _FORBIDDEN_NATIVE_OPTIONS):
            raise _fail(HOST_DEPENDENT_COMPILER_OPTION_FORBIDDEN, f"{label} uses a host-native option")
    return command


def validate_effective_frontend_state(value: Any) -> list[Any]:
    row = _array(value, "effective_frontend_state")
    if len(row) != 11:
        raise _fail(EFFECTIVE_CC1_COMMAND_INVALID, "effective frontend state has the wrong width")
    argv = _command(row[0], "effective_cc1_argv")
    if len(argv) < 2 or _canonical_path(argv[0], "effective compiler entry path") != argv[0] or argv[1] != "-cc1":
        raise _fail(EFFECTIVE_CC1_COMMAND_INVALID, "effective command must start with compiler path and -cc1")
    if argv[2:].count("-cc1") or argv.count("-cc1") != 1:
        raise _fail(UNSUPPORTED_FRONTEND_ACTION_COUNT, "effective command must contain exactly one frontend action")
    target = _text(row[1], "target triple")
    if not target or any(character.isspace() for character in target):
        raise _fail(EFFECTIVE_TARGET_TRIPLE_INVALID, "effective target triple is invalid")
    language_kind = _uint(row[2], 8, "language kind")
    standard = _text(row[3], "language standard")
    if language_kind != LANGUAGE_CXX or not standard:
        raise _fail(EFFECTIVE_LANGUAGE_MODE_INVALID, "effective language must be canonical CXX")
    resource_dir = _canonical_path(row[4], "resource directory", allow_empty=True)
    sysroot = _canonical_path(row[5], "sysroot", allow_empty=True)
    implicit = [
        _uint(row[6], 8, "modules enabled"),
        _uint(row[7], 16, "PCH input count"),
        _uint(row[8], 16, "PCM input count"),
        _uint(row[9], 16, "VFS overlay count"),
        _uint(row[10], 16, "frontend plugin count"),
    ]
    if any(implicit):
        raise _fail(UNSUPPORTED_IMPLICIT_COMPILER_STATE, "implicit frontend state is not supported")
    return [argv, target, language_kind, standard, resource_dir, sysroot, *implicit]


def _environment(value: Any) -> list[list[str]]:
    result: list[list[str]] = []
    for item in _array(value, "environment"):
        pair = _array(item, "environment pair")
        if len(pair) != 2:
            raise _fail(EFFECTIVE_CC1_COMMAND_INVALID, "environment pair has the wrong width")
        result.append([_text(pair[0], "environment key"), _text(pair[1], "environment value")])
    if result != ENVIRONMENT:
        raise _fail(EFFECTIVE_CC1_COMMAND_INVALID, "environment is not the frozen compiler environment")
    return result


def tu_semantics_root(
    *,
    source_root: bytes,
    toolchain_runtime_root: bytes,
    compiler_binary_sha256: bytes,
    extractor_binary_sha256: bytes,
    compiler_semantics_root: bytes,
    tu_ordinal: int,
    primary_source_virtual_path: str,
    working_directory: str,
    source_mount: str,
    toolchain_mount: str,
    environment: Any,
    compiler_command: Any,
    extractor_command: Any,
    effective_frontend_state: Any,
) -> bytes:
    source_mount_value = _canonical_path(source_mount, "source_mount")
    toolchain_mount_value = _canonical_path(toolchain_mount, "toolchain_mount")
    working = _canonical_path(working_directory, "working_directory")
    if [working, source_mount_value, toolchain_mount_value] != [
        "/v631302/work",
        "/v631302/src",
        "/v631302/toolchain",
    ]:
        raise _fail(EFFECTIVE_CC1_COMMAND_INVALID, "state-3 virtual mounts are not exact")
    primary_path = _canonical_path(primary_source_virtual_path, "primary_source_virtual_path")
    if not _inside(primary_path, source_mount_value) or primary_path == source_mount_value:
        raise _fail(TU_PRIMARY_INPUT_INVALID, "primary source path is outside the source mount")
    compiler = _command(compiler_command, "compiler_command")
    extractor = _command(extractor_command, "extractor_command")
    if compiler[0] == extractor[0]:
        raise _fail(EFFECTIVE_CC1_COMMAND_INVALID, "compiler and extractor entrypoints must differ")
    frontend = validate_effective_frontend_state(effective_frontend_state)
    if frontend[0][0] != compiler[0]:
        raise _fail(EFFECTIVE_CC1_COMMAND_INVALID, "effective compiler entry differs from the driver command")
    for path in frontend[4:6]:
        if path and not _inside(path, toolchain_mount_value):
            raise _fail(EFFECTIVE_RESOURCE_PATH_INVALID, "effective resource path is outside the runtime mount")
    value = [
        PROTOCOL_ID,
        TU_SEMANTICS_VERSION,
        _bstr32(source_root, "source_root"),
        _bstr32(toolchain_runtime_root, "toolchain_runtime_root"),
        _bstr32(compiler_binary_sha256, "compiler_binary_sha256"),
        _bstr32(extractor_binary_sha256, "extractor_binary_sha256"),
        _bstr32(compiler_semantics_root, "compiler_semantics_root"),
        _uint(tu_ordinal, 32, "tu_ordinal"),
        primary_path,
        working,
        source_mount_value,
        toolchain_mount_value,
        _environment(environment),
        compiler,
        extractor,
        frontend,
    ]
    return _hash(DS_TU_SEMANTICS_ROOT, value)


def linkage_scope_id(
    *,
    source_root: bytes,
    target_root: bytes,
    tu_ordinal: int,
    primary_source_virtual_path: str,
    tu_content_root: bytes,
    tu_semantics_root: bytes,
) -> bytes:
    primary = _canonical_path(primary_source_virtual_path, "primary_source_virtual_path")
    if not _inside(primary, "/v631302/src") or primary == "/v631302/src":
        raise _fail(TU_SCOPE_EVIDENCE_INCOMPLETE, "TU primary path is outside the source mount")
    value = [
        PROTOCOL_ID,
        1,
        _bstr32(source_root, "source_root"),
        _bstr32(target_root, "target_root"),
        _uint(tu_ordinal, 32, "tu_ordinal"),
        primary,
        _bstr32(tu_content_root, "tu_content_root"),
        _bstr32(tu_semantics_root, "tu_semantics_root"),
    ]
    return _hash(DS_LINKAGE_SCOPE_ID, value)


def _primary_observation(value: Any, expected_path: str) -> list[Any]:
    row = _array(value, "primary_input_observation")
    if len(row) != 3 or row[0] != SOURCE_ORIGIN:
        raise _fail(TU_PRIMARY_INPUT_INVALID, "primary input observation is invalid")
    path = _physical_path(SOURCE_ORIGIN, row[1], "primary observation path")
    if path != expected_path:
        raise _fail(TU_PRIMARY_INPUT_INVALID, "primary observation path differs from the TU path")
    return [SOURCE_ORIGIN, path, _uint(row[2], 32, "primary activation count", positive=True)]


def _dependency_observations(value: Any, primary_path: str) -> list[list[Any]]:
    commitments = []
    for item in _array(value, "dependency_observations"):
        row = _array(item, "dependency_observation")
        if len(row) != 4:
            raise _fail(TU_DEPENDENCY_PATH_INVALID, "dependency observation has the wrong width")
        commitments.append([row[0], row[1], row[2], 0, ZERO32, row[3]])
    normalized = _dependency_commitments(commitments, primary_path)
    return [[row[0], row[1], row[2], row[5]] for row in normalized]


def _virtual_observations(value: Any) -> list[list[Any]]:
    observations: list[list[Any]] = []
    commitments: list[list[Any]] = []
    for item in _array(value, "virtual_input_observations"):
        row = _array(item, "virtual_input_observation")
        if len(row) != 5:
            raise _fail(TU_VIRTUAL_INPUT_INVALID, "virtual input observation has the wrong width")
        content = _bstr(row[3], "virtual input bytes")
        commitments.append([row[0], row[1], row[2], len(content), sha256(content).digest(), row[4]])
        observations.append([
            _uint(row[0], 32, "virtual ordinal"),
            _uint(row[1], 8, "virtual kind"),
            _text(row[2], "virtual logical name"),
            content,
            _uint(row[4], 32, "virtual activation count", positive=True),
        ])
    _virtual_commitments(commitments)
    return observations


def _schema_array(value: Any, label: str, code: str) -> Sequence[Any]:
    if type(value) not in (list, tuple):
        raise _fail(code, f"{label} must be a CBOR array")
    return value


def _schema_uint(value: Any, bits: int, label: str, code: str) -> int:
    if type(value) is not int or value < 0 or value >= _UINT_LIMITS[bits]:
        raise _fail(code, f"{label} must fit uint{bits}")
    return value


def _schema_text(value: Any, label: str, code: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise _fail(code, f"{label} must be nonempty NUL-free text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(code, f"{label} is not strict UTF-8") from exc
    return value


def _callable_decl_kind(value: Any, *, callee: bool) -> str:
    code = CALLEE_DECL_KIND_UNSUPPORTED if callee else DEFINITION_DECL_KIND_UNSUPPORTED
    kind = _schema_text(value, "ast_decl_kind", code)
    if kind not in _CALLABLE_DECL_KINDS:
        raise _fail(code, f"unsupported callable declaration kind: {kind}")
    return kind


def _linkage_code(value: Any) -> int:
    linkage = _schema_uint(value, 8, "linkage_code", LINKAGE_CLASS_UNSUPPORTED)
    if linkage not in (LINKAGE_ODR_MERGEABLE, LINKAGE_TRANSLATION_UNIT_LOCAL):
        raise _fail(LINKAGE_CLASS_UNSUPPORTED, "linkage code is reserved")
    return linkage


def _validate_callee_descriptor(
    value: Any,
    *,
    authenticated_terminal_context: bool,
) -> list[Any]:
    row = _schema_array(value, "callee_descriptor", CALLEE_DESCRIPTOR_SCHEMA_INVALID)
    if len(row) != 5:
        raise _fail(CALLEE_DESCRIPTOR_SCHEMA_INVALID, "callee descriptor has the wrong width")
    kind = _callable_decl_kind(row[0], callee=True)
    name = _schema_text(row[1], "qualified_name", CALLEE_DESCRIPTOR_SCHEMA_INVALID)
    raw_type = _schema_text(row[2], "raw_qual_type", CALLEE_DESCRIPTOR_SCHEMA_INVALID)
    qtid_ascii_v1(raw_type)
    linkage = _linkage_code(row[3])
    origin = _schema_uint(row[4], 8, "origin_code", CALLEE_ORIGIN_INVALID)
    if origin not in _CALLEE_ORIGINS:
        raise _fail(CALLEE_ORIGIN_INVALID, "callee origin code is reserved")
    if origin in (2, 3) and not authenticated_terminal_context:
        raise _fail(
            CALLEE_TERMINAL_CONTEXT_REQUIRED,
            "authenticated callee origin requires registry and implementation-closure context",
        )
    if origin == 3 and linkage != LINKAGE_ODR_MERGEABLE:
        raise _fail(CALLEE_ORIGIN_INVALID, "compiler builtins must use ODR linkage")
    return [kind, name, raw_type, linkage, origin]


def validate_callee_descriptor(value: Any) -> list[Any]:
    """Validate a descriptor without accepting unauthenticated terminals.

    Origins 2 and 3 have semantic evidence requirements that a standalone
    wire-shape validator cannot establish.  The reducer uses the private
    context-aware path only after validating the exact terminal and
    implementation roots.
    """

    return _validate_callee_descriptor(
        value,
        authenticated_terminal_context=False,
    )


def _validate_callee_descriptors(
    value: Any,
    invocation_kind: int,
    *,
    authenticated_terminal_context: bool,
) -> list[list[Any]]:
    rows = [
        _validate_callee_descriptor(
            item,
            authenticated_terminal_context=authenticated_terminal_context,
        )
        for item in _schema_array(value, "callee_descriptors", CALLEE_DESCRIPTOR_SCHEMA_INVALID)
    ]
    if not rows:
        raise _fail(CALLEE_RESOLUTION_CARDINALITY_INVALID, "callee descriptor set is empty")
    encoded = [eir_canonical_cbor_encode(row) for row in rows]
    if len(encoded) != len(set(encoded)):
        raise _fail(CALLEE_DESCRIPTOR_DUPLICATE, "callee descriptor is duplicated")
    if encoded != sorted(encoded):
        raise _fail(CALLEE_DESCRIPTOR_ORDER_INVALID, "callee descriptors are not canonically sorted")
    identity_keys = [
        eir_canonical_cbor_encode([row[0], row[1], qtid_ascii_v1(row[2]), row[3]])
        for row in rows
    ]
    if len(identity_keys) != len(set(identity_keys)):
        raise _fail(
            CALLEE_DESCRIPTOR_IDENTITY_COLLISION,
            "distinct descriptors normalize to one declaration identity",
        )
    if invocation_kind == 8:
        if any(row[4] != 3 for row in rows):
            raise _fail(CALLEE_ORIGIN_INVALID, "compiler-builtin calls require builtin callees")
    elif any(row[4] == 3 for row in rows):
        raise _fail(CALLEE_ORIGIN_INVALID, "compiler builtin callee has the wrong invocation kind")
    return rows


def _anchor_path(value: Any) -> list[int]:
    return [
        _schema_uint(item, 32, "anchor AST path component", AST_ANCHOR_PATH_INVALID)
        for item in _schema_array(value, "anchor_ast_path", AST_ANCHOR_PATH_INVALID)
    ]


def _validate_invocation_occurrences(
    value: Any,
    *,
    authenticated_terminal_context: bool,
) -> list[list[Any]]:
    rows: list[list[Any]] = []
    ordering: list[tuple[tuple[int, ...], int, int, bytes]] = []
    for expected_ordinal, value_row in enumerate(
        _schema_array(value, "invocation_occurrences", INVOCATION_OCCURRENCE_SCHEMA_INVALID)
    ):
        row = _schema_array(value_row, "invocation_occurrence", INVOCATION_OCCURRENCE_SCHEMA_INVALID)
        if len(row) != 5:
            raise _fail(INVOCATION_OCCURRENCE_SCHEMA_INVALID, "invocation occurrence has the wrong width")
        ordinal = _schema_uint(
            row[0], 32, "occurrence_ordinal", INVOCATION_OCCURRENCE_ORDINAL_INVALID
        )
        if ordinal != expected_ordinal:
            raise _fail(INVOCATION_OCCURRENCE_ORDINAL_INVALID, "occurrence ordinals are not dense")
        path = _anchor_path(row[1])
        invocation_kind = _schema_uint(row[2], 8, "invocation_kind", INVOCATION_KIND_INVALID)
        if invocation_kind not in INVOCATION_KINDS:
            raise _fail(INVOCATION_KIND_INVALID, "invocation kind is reserved")
        resolution_kind = _schema_uint(row[3], 8, "resolution_kind", RESOLUTION_KIND_INVALID)
        if resolution_kind not in (RESOLUTION_EXACT_SINGLE, RESOLUTION_EXACT_FINITE_SET):
            raise _fail(RESOLUTION_KIND_INVALID, "resolution kind is not exact and finite")
        descriptors = _validate_callee_descriptors(
            row[4],
            invocation_kind,
            authenticated_terminal_context=authenticated_terminal_context,
        )
        if resolution_kind == RESOLUTION_EXACT_SINGLE and len(descriptors) != 1:
            raise _fail(CALLEE_RESOLUTION_CARDINALITY_INVALID, "exact-single requires one callee")
        if resolution_kind == RESOLUTION_EXACT_FINITE_SET and len(descriptors) < 2:
            raise _fail(CALLEE_RESOLUTION_CARDINALITY_INVALID, "finite-set requires at least two callees")
        rows.append([ordinal, path, invocation_kind, resolution_kind, descriptors])
        ordering.append(
            (tuple(path), invocation_kind, resolution_kind, eir_canonical_cbor_encode(descriptors))
        )
    if ordering != sorted(ordering):
        raise _fail(INVOCATION_OCCURRENCE_ORDER_INVALID, "invocation occurrences are not canonically ordered")
    return rows


def validate_invocation_occurrences(value: Any) -> list[list[Any]]:
    """Validate raw occurrences without authenticated terminal context."""

    return _validate_invocation_occurrences(
        value,
        authenticated_terminal_context=False,
    )


def validate_definition_instance_observations(value: Any) -> list[list[Any]]:
    definitions: list[list[Any]] = []
    ordering: list[bytes] = []
    target_owners: dict[int, int] = {}
    for expected_ordinal, value_row in enumerate(
        _schema_array(
            value,
            "definition_instance_observations",
            EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
        )
    ):
        row = _schema_array(
            value_row,
            "definition_instance_observation",
            EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
        )
        if len(row) != 10:
            raise _fail(
                EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
                "definition observation has the wrong width",
            )
        ordinal = _schema_uint(
            row[0], 32, "instance_ordinal", EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE
        )
        if ordinal != expected_ordinal:
            raise _fail(
                EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
                "definition instance ordinals are not dense",
            )
        kind = _callable_decl_kind(row[1], callee=False)
        name = _schema_text(
            row[2], "qualified_name", EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE
        )
        raw_type = _schema_text(
            row[3], "raw_qual_type", EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE
        )
        qtid_ascii_v1(raw_type)
        linkage = _linkage_code(row[4])
        target_indices = [
            _schema_uint(item, 32, "target_index", TARGET_INDEX_OUT_OF_RANGE)
            for item in _schema_array(row[5], "target_indices", TARGET_INDEX_ORDER_INVALID)
        ]
        if any(index > 115 for index in target_indices):
            raise _fail(TARGET_INDEX_OUT_OF_RANGE, "target index is outside 0..115")
        if len(target_indices) != len(set(target_indices)):
            raise _fail(TARGET_INDEX_DUPLICATE, "target index is duplicated")
        if target_indices != sorted(target_indices):
            raise _fail(TARGET_INDEX_ORDER_INVALID, "target indices are not strictly increasing")
        for index in target_indices:
            if index in target_owners:
                raise _fail(
                    TARGET_INDEX_MULTIPLE_DEFINITIONS_IN_TU,
                    "one target index belongs to multiple definitions in a TU",
                )
            target_owners[index] = ordinal
        path = _canonical_path(row[6], "definition_virtual_path")
        if not _inside(path, "/v631302/src") or path == "/v631302/src":
            raise _fail(
                EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
                "definition span is outside the source mount",
            )
        begin = _schema_uint(
            row[7], 64, "definition_begin_offset", EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE
        )
        end = _schema_uint(
            row[8],
            64,
            "definition_end_offset_exclusive",
            EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
        )
        if end <= begin:
            raise _fail(
                EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
                "definition source span must be nonempty",
            )
        occurrences = validate_invocation_occurrences(row[9])
        definition = [
            ordinal,
            kind,
            name,
            raw_type,
            linkage,
            target_indices,
            path,
            begin,
            end,
            occurrences,
        ]
        definitions.append(definition)
        ordering.append(eir_canonical_cbor_encode(definition[1:9]))
    if len(ordering) != len(set(ordering)):
        raise _fail(
            EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
            "definition identity/span ordering keys are duplicated",
        )
    if ordering != sorted(ordering):
        raise _fail(
            EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
            "definition observations are not canonically ordered",
        )
    return definitions


def _function_ref(value: Any, label: str) -> list[Any]:
    row = _schema_array(value, label, INVOCATION_REDUCTION_MISMATCH)
    if len(row) != 2:
        raise _fail(INVOCATION_REDUCTION_MISMATCH, f"{label} has the wrong width")
    kind = _schema_uint(row[0], 8, f"{label} kind", INVOCATION_REDUCTION_MISMATCH)
    if kind == TARGET_REF:
        return [kind, _schema_uint(row[1], 32, f"{label} target", INVOCATION_REDUCTION_MISMATCH)]
    if kind == HELPER_REF:
        value_id = row[1]
        if type(value_id) is not bytes or len(value_id) != 32:
            raise _fail(INVOCATION_REDUCTION_MISMATCH, f"{label} helper ID must be bstr32")
        return [kind, value_id]
    if kind == TERMINAL_REF:
        return [kind, _schema_uint(row[1], 32, f"{label} terminal", INVOCATION_REDUCTION_MISMATCH)]
    raise _fail(INVOCATION_REDUCTION_MISMATCH, f"{label} kind is reserved")


def _descriptor_declaration_key(descriptor: Sequence[Any], linkage_scope: bytes) -> list[Any]:
    scope = ZERO32 if descriptor[3] == LINKAGE_ODR_MERGEABLE else linkage_scope
    return validate_declaration_key(
        [descriptor[0], descriptor[1], descriptor[2], qtid_ascii_v1(descriptor[2]), descriptor[3], scope]
    )


def reduce_invocation_occurrences(
    value: Any,
    *,
    current_linkage_scope_id: bytes,
    source_definition_refs: Any,
    backend_matcher_registry: Any,
    external_terminal_registry: Any,
    compiler_semantics_root: bytes,
    expected_backend_matcher_root: bytes,
    expected_external_terminal_root: bytes,
    toolchain_runtime_root: bytes,
) -> list[list[Any]]:
    """Reduce validated raw occurrences to exact prebinding-v2 rows.

    The explicit source/terminal tables are comparison inputs, not evidence.
    This pure reducer cannot establish compiler execution, global definition
    closure, ODR equivalence, or any State-3 authority.
    """

    scope = _bstr32(current_linkage_scope_id, "current_linkage_scope_id")
    if scope == ZERO32:
        raise _fail(INVOCATION_REDUCTION_MISMATCH, "TU-local linkage scope must be nonzero")
    semantics_root = _bstr32(compiler_semantics_root, "compiler_semantics_root")
    matcher_root = _bstr32(expected_backend_matcher_root, "expected_backend_matcher_root")
    terminal_root = _bstr32(
        expected_external_terminal_root, "expected_external_terminal_root"
    )
    runtime_root = _bstr32(toolchain_runtime_root, "toolchain_runtime_root")
    source_by_key: dict[bytes, list[list[Any]]] = {}
    for item in _schema_array(
        source_definition_refs, "source_definition_refs", INVOCATION_REDUCTION_MISMATCH
    ):
        row = _schema_array(item, "source_definition_ref", INVOCATION_REDUCTION_MISMATCH)
        if len(row) != 2:
            raise _fail(INVOCATION_REDUCTION_MISMATCH, "source definition ref has the wrong width")
        declaration = validate_declaration_key(row[0])
        ref = _function_ref(row[1], "source callee ref")
        if ref[0] == TERMINAL_REF:
            raise _fail(INVOCATION_REDUCTION_MISMATCH, "source definition cannot resolve to terminal")
        source_by_key.setdefault(eir_canonical_cbor_encode(declaration), []).append(ref)

    validated_backend_registry = validate_backend_matcher_registry(
        backend_matcher_registry,
        expected_compiler_semantics_root=semantics_root,
    )
    if compute_backend_matcher_root(validated_backend_registry) != matcher_root:
        raise _fail(PREBINDING_ROOT_MISMATCH, "backend matcher registry root mismatch")
    validated_terminal_registry = validate_external_terminal_registry(
        external_terminal_registry,
        backend_registry=validated_backend_registry,
        expected_compiler_semantics_root=semantics_root,
        expected_backend_matcher_root=matcher_root,
        expected_toolchain_runtime_root=runtime_root,
    )
    if compute_external_terminal_root(validated_terminal_registry) != terminal_root:
        raise _fail(PREBINDING_ROOT_MISMATCH, "external terminal registry root mismatch")
    terminals_by_key: dict[bytes, list[list[Any]]] = {}
    for terminal in validated_terminal_registry[3]:
        terminals_by_key.setdefault(
            eir_canonical_cbor_encode(terminal[2]), []
        ).append(terminal)

    occurrences = _validate_invocation_occurrences(
        value,
        authenticated_terminal_context=True,
    )

    def resolve(descriptor: Sequence[Any]) -> list[Any]:
        declaration = _descriptor_declaration_key(descriptor, scope)
        key = eir_canonical_cbor_encode(declaration)
        origin = descriptor[4]
        terminals = terminals_by_key.get(key, [])
        if origin == 1:
            if terminals:
                raise _fail(CALLEE_ORIGIN_INVALID, "terminal classification takes precedence")
            matches = source_by_key.get(key, [])
            if not matches:
                raise _fail(CALLEE_SOURCE_DEFINITION_NOT_FOUND, "source callee is absent")
            if len(matches) != 1:
                raise _fail(CALLEE_SOURCE_DEFINITION_AMBIGUOUS, "source callee is ambiguous")
            return matches[0]
        if origin == 2:
            matches = [
                row
                for row in terminals
                if row[1] == 1 or (row[1] == 2 and row[3] == 0 and row[4] == 2)
            ]
            if not matches:
                raise _fail(CALLEE_TERMINAL_NOT_FOUND, "authenticated terminal is absent")
            if len(matches) != 1:
                raise _fail(CALLEE_TERMINAL_AMBIGUOUS, "authenticated terminal is ambiguous")
            return [TERMINAL_REF, matches[0][0]]
        matches = [
            row
            for row in terminals
            if row[1] == 2
            and row[3] == 0
            and row[4] == 3
            and row[5] == runtime_root
            and declaration[4] == LINKAGE_ODR_MERGEABLE
            and declaration[5] == ZERO32
        ]
        if len(matches) != 1:
            raise _fail(
                CALLEE_BUILTIN_TERMINAL_MISMATCH,
                "compiler builtin does not match exactly one runtime-bound terminal",
            )
        return [TERMINAL_REF, matches[0][0]]

    grouped: dict[bytes, tuple[list[int], int, int, list[list[Any]], int]] = {}
    for occurrence in occurrences:
        refs = [resolve(descriptor) for descriptor in occurrence[4]]
        encoded_refs = [eir_canonical_cbor_encode(ref) for ref in refs]
        if len(encoded_refs) != len(set(encoded_refs)):
            raise _fail(CALLEE_REF_ALIAS_COLLISION, "distinct descriptors resolve to one callee ref")
        refs = [ref for _, ref in sorted(zip(encoded_refs, refs), key=lambda item: item[0])]
        if occurrence[3] == RESOLUTION_EXACT_SINGLE and len(refs) != 1:
            raise _fail(CALLEE_RESOLUTION_CARDINALITY_INVALID, "reduced exact-single is not singular")
        if occurrence[3] == RESOLUTION_EXACT_FINITE_SET and len(refs) < 2:
            raise _fail(CALLEE_RESOLUTION_CARDINALITY_INVALID, "reduced finite set has fewer than two refs")
        group_value = [occurrence[1], occurrence[2], occurrence[3], refs]
        group_key = eir_canonical_cbor_encode(group_value)
        prior = grouped.get(group_key)
        count = 1 if prior is None else prior[4] + 1
        if count >= _UINT_LIMITS[32]:
            raise _fail(INVOCATION_OCCURRENCE_COUNT_OVERFLOW, "group occurrence count exceeds uint32")
        grouped[group_key] = (occurrence[1], occurrence[2], occurrence[3], refs, count)

    groups = sorted(
        grouped.values(),
        key=lambda item: (
            tuple(item[0]),
            eir_canonical_cbor_encode([item[1], item[2], item[3]]),
        ),
    )
    rows: list[list[Any]] = []
    prior_path: tuple[int, ...] | None = None
    semantic_slot = 0
    for ordinal, (path, invocation_kind, resolution_kind, refs, count) in enumerate(groups):
        path_key = tuple(path)
        if path_key != prior_path:
            semantic_slot = 0
            prior_path = path_key
        rows.append(
            [ordinal, path, semantic_slot, invocation_kind, resolution_kind, count, refs]
        )
        semantic_slot += 1
    if sum(row[5] for row in rows) != len(occurrences):
        raise _fail(INVOCATION_REDUCTION_MISMATCH, "group counts do not equal raw occurrences")
    return rows


def validate_extractor_tu_observation_v2(value: Any) -> list[Any]:
    """Validate the frozen observation wire shape and per-TU coverage closure."""

    row = _array(value, "extractor_tu_observation_v2")
    if len(row) != 11 or list(row[:2]) != [PROTOCOL_ID, EXTRACTOR_OBSERVATION_VERSION]:
        raise _fail(EXTRACTOR_OBSERVATION_VERSION_UNSUPPORTED, "extractor observation header is invalid")
    ordinal = _uint(row[2], 32, "tu_ordinal")
    primary_path = _canonical_path(row[3], "primary_source_virtual_path")
    if not _inside(primary_path, "/v631302/src") or primary_path == "/v631302/src":
        raise _fail(TU_PRIMARY_INPUT_INVALID, "extractor TU path is outside the source mount")
    frontend = validate_effective_frontend_state(row[4])
    primary = _primary_observation(row[5], primary_path)
    dependencies = _dependency_observations(row[6], primary_path)
    predefines = _bstr(row[7], "predefines bytes")
    virtual = _virtual_observations(row[8])
    definitions = validate_definition_instance_observations(row[9])
    coverage = [_uint(item, 32, "extractor coverage count") for item in _array(row[10], "coverage_counts")]
    if len(coverage) != 14:
        raise _fail(EXTRACTOR_INPUT_CLOSURE_INCOMPLETE, "coverage array has the wrong width")
    emitted_file_activations = primary[2] + sum(item[3] for item in dependencies)
    emitted_regular_inputs = 1 + len(dependencies)
    emitted_virtual_activations = sum(item[4] for item in virtual)
    if coverage[:6] != [
        emitted_file_activations,
        emitted_file_activations,
        emitted_regular_inputs,
        emitted_regular_inputs,
        emitted_virtual_activations,
        emitted_virtual_activations,
    ]:
        raise _fail(EXTRACTOR_INPUT_CLOSURE_INCOMPLETE, "physical-input coverage is incomplete")
    if coverage[6] != coverage[7] or coverage[7] != len(definitions):
        raise _fail(DEFINITION_COVERAGE_COUNT_MISMATCH, "definition coverage counts do not close")
    emitted_invocations = sum(len(definition[9]) for definition in definitions)
    if coverage[9] != emitted_invocations or coverage[8] != coverage[9] + coverage[10] + coverage[11]:
        raise _fail(
            INVOCATION_COVERAGE_ACCOUNTING_MISMATCH,
            "invocation coverage accounting identity does not hold",
        )
    if coverage[10] or coverage[11]:
        raise _fail(
            EXTRACTOR_INVOCATION_CLOSURE_INCOMPLETE,
            "unresolved or unsupported invocation facts remain",
        )
    if coverage[12]:
        raise _fail(
            EXTRACTOR_DEFINITION_CLOSURE_INCOMPLETE,
            "unsupported implicit source definitions remain",
        )
    if coverage[13]:
        raise _fail(
            EXTRACTOR_INPUT_CLOSURE_INCOMPLETE,
            "nondeterministic builtin expansions remain",
        )
    return [
        PROTOCOL_ID,
        EXTRACTOR_OBSERVATION_VERSION,
        ordinal,
        primary_path,
        frontend,
        primary,
        dependencies,
        predefines,
        virtual,
        definitions,
        coverage,
    ]


def decode_extractor_tu_observation_v2_bytes(raw: bytes) -> list[Any]:
    """Decode exactly one raw-UTF-8 EIR CBOR observation from extractor stdout."""

    return validate_extractor_tu_observation_v2(eir_canonical_cbor_decode(raw))


def zero_authority_status() -> dict[str, Any]:
    return {
        "state": "STATE3_PRIMITIVES_ONLY",
        "compiler_recomputed": False,
        "external_evidence_valid": False,
        "eir_freeze_authority": False,
        "authority": AUTHORITY,
        "engine_wiring_authority": ENGINE_WIRING_AUTHORITY,
        "campaign_root_authority": False,
        "assignment_authority": False,
        "preregistration_authority": False,
        "permit_authority": PERMIT_AUTHORITY,
        "agent_modification_authority": AGENT_MODIFICATION_AUTHORITY,
        "sealed_holdout_access_authority": SEALED_HOLDOUT_ACCESS_AUTHORITY,
        "calibration_upload_authority": CALIBRATION_UPLOAD_AUTHORITY,
        "production_upload_authority": PRODUCTION_UPLOAD_AUTHORITY,
        "upload_authority": UPLOAD_AUTHORITY,
        "holdout_access_authority": HOLDOUT_ACCESS_AUTHORITY,
    }


__all__ = [
    "CALIBRATION_UPLOAD_AUTHORITY",
    "COMPILER_RECOMPUTED",
    "DEFAULT_SOURCE_TREE_LIMITS",
    "DS_LINKAGE_SCOPE_ID",
    "DS_STATE3_EXECUTION_PROFILE",
    "DS_STATE3_LOCAL_TRUST_ALLOWLIST_ROOT",
    "DS_TU_CONTENT_ROOT",
    "DS_TU_SEMANTICS_ROOT",
    "EIR_FREEZE_AUTHORITY",
    "EXTERNAL_EVIDENCE_VALID",
    "PINNED_STATE3_LOCAL_TRUST_ALLOWLIST_ROOT",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "SEALED_HOLDOUT_ACCESS_AUTHORITY",
    "SourceTreeLimits",
    "linkage_scope_id",
    "source_tree_sha256",
    "source_tree_sha256_fd",
    "state3_execution_profile_id",
    "state3_local_trust_allowlist_root",
    "tu_content_root",
    "tu_semantics_root",
    "reduce_invocation_occurrences",
    "decode_extractor_tu_observation_v2_bytes",
    "validate_callee_descriptor",
    "validate_definition_instance_observations",
    "validate_effective_frontend_state",
    "validate_extractor_tu_observation_v2",
    "validate_invocation_occurrences",
    "validate_state3_execution_profile",
    "validate_state3_local_trust_allowlist",
    "zero_authority_status",
]
