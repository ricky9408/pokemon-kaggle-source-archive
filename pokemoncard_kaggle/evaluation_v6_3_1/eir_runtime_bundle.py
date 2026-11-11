"""Bounded, zero-authority verification of a v6.3.1 runtime bundle.

The v6.3.1 runtime manifest describes a filesystem mapped to virtual ``/``.
This module can enumerate that mapping and can compare a manifest with every
inode visible below a supplied rootfs.  It deliberately stops at byte
verification: it does not establish compiler recomputation, external
evidence, EIR freeze, or any upload/holdout authority.

The filesystem is not assumed to provide an atomic snapshot.  Regular-file
reads use lstat/open/fstat/read/fstat/lstat checks, and directory scans are
checked before and after enumeration.  Those checks catch ordinary races but
cannot prove immutability against a hostile filesystem without a sealed
snapshot or equivalent kernel-level guarantee; that limitation is reported
on every result.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence

from .eir_prebinding import (
    EIRPrebindingError,
    ZERO32,
    toolchain_runtime_root,
    validate_toolchain_runtime_manifest,
)


RUNTIME_BUNDLE_INVALID_ROOT = "RUNTIME_BUNDLE_INVALID_ROOT"
RUNTIME_BUNDLE_ROOT_NOT_DIRECTORY = "RUNTIME_BUNDLE_ROOT_NOT_DIRECTORY"
RUNTIME_BUNDLE_PATH_UNSAFE = "RUNTIME_BUNDLE_PATH_UNSAFE"
RUNTIME_BUNDLE_PATH_ENCODING = "RUNTIME_BUNDLE_PATH_ENCODING"
RUNTIME_BUNDLE_SPECIAL_INODE = "RUNTIME_BUNDLE_SPECIAL_INODE"
RUNTIME_BUNDLE_IO_ERROR = "RUNTIME_BUNDLE_IO_ERROR"
RUNTIME_BUNDLE_RACE_DETECTED = "RUNTIME_BUNDLE_RACE_DETECTED"
RUNTIME_BUNDLE_LIMIT_EXCEEDED = "RUNTIME_BUNDLE_LIMIT_EXCEEDED"
RUNTIME_BUNDLE_MISSING_OBJECT = "RUNTIME_BUNDLE_MISSING_OBJECT"
RUNTIME_BUNDLE_UNMANIFESTED_OBJECT = "RUNTIME_BUNDLE_UNMANIFESTED_OBJECT"
RUNTIME_BUNDLE_OBJECT_DRIFT = "RUNTIME_BUNDLE_OBJECT_DRIFT"
RUNTIME_BUNDLE_FILE_SIZE_DRIFT = "RUNTIME_BUNDLE_FILE_SIZE_DRIFT"
RUNTIME_BUNDLE_FILE_DIGEST_DRIFT = "RUNTIME_BUNDLE_FILE_DIGEST_DRIFT"
RUNTIME_BUNDLE_PERMISSION_DRIFT = "RUNTIME_BUNDLE_PERMISSION_DRIFT"
RUNTIME_BUNDLE_SYMLINK_TARGET_DRIFT = "RUNTIME_BUNDLE_SYMLINK_TARGET_DRIFT"
RUNTIME_BUNDLE_SYMLINK_ESCAPE = "RUNTIME_BUNDLE_SYMLINK_ESCAPE"
RUNTIME_BUNDLE_SYMLINK_CYCLE = "RUNTIME_BUNDLE_SYMLINK_CYCLE"
RUNTIME_BUNDLE_SYMLINK_TARGET_MISSING = "RUNTIME_BUNDLE_SYMLINK_TARGET_MISSING"
RUNTIME_BUNDLE_ENTRYPOINT_MISSING = "RUNTIME_BUNDLE_ENTRYPOINT_MISSING"
RUNTIME_BUNDLE_ENTRYPOINT_NOT_REGULAR = "RUNTIME_BUNDLE_ENTRYPOINT_NOT_REGULAR"
RUNTIME_BUNDLE_ENTRYPOINT_NOT_EXECUTABLE = "RUNTIME_BUNDLE_ENTRYPOINT_NOT_EXECUTABLE"
SCRIPT_ENTRYPOINT_FORBIDDEN = "SCRIPT_ENTRYPOINT_FORBIDDEN"
RUNTIME_BUNDLE_ENTRYPOINT_SHEBANG = SCRIPT_ENTRYPOINT_FORBIDDEN
RUNTIME_BUNDLE_ENTRYPOINT_SIZE_DRIFT = "RUNTIME_BUNDLE_ENTRYPOINT_SIZE_DRIFT"
RUNTIME_BUNDLE_ENTRYPOINT_DIGEST_DRIFT = "RUNTIME_BUNDLE_ENTRYPOINT_DIGEST_DRIFT"
RUNTIME_BUNDLE_NO_NOFOLLOW = "RUNTIME_BUNDLE_NO_NOFOLLOW"
RUNTIME_RESERVED_PATH_COLLISION = "RUNTIME_RESERVED_PATH_COLLISION"


_RESERVED_RUNTIME_PREFIXES = (
    "/dev",
    "/proc",
    "/sys",
    "/v631302/input",
    "/v631302/src",
    "/v631302/work",
)


_LIMITATION_TEXT = (
    "The host filesystem is not an atomic snapshot; lstat/open/fstat/read checks "
    "detect ordinary TOCTOU changes but cannot prove immutability against a "
    "hostile concurrent filesystem without a sealed snapshot.",
    "This verifier proves only rootfs bytes, inode metadata, symlink topology, "
    "and entrypoint safety; it does not prove compiler recomputation, external "
    "terminal evidence, EIR completeness, archive custody, or any authority.",
)


@dataclass(frozen=True)
class RuntimeBundleLimits:
    """Resource limits for a bounded rootfs walk and byte read."""

    max_entries: int = 250_000
    max_file_bytes: int = 1 << 34
    max_total_file_bytes: int = 1 << 40
    max_path_bytes: int = 4096
    max_symlink_hops: int = 4096
    read_chunk_bytes: int = 1 << 20

    def validate(self) -> None:
        values = (
            self.max_entries,
            self.max_file_bytes,
            self.max_total_file_bytes,
            self.max_path_bytes,
            self.max_symlink_hops,
            self.read_chunk_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("runtime bundle limits must be positive integers")
        if self.max_file_bytes > self.max_total_file_bytes:
            raise ValueError("max_file_bytes cannot exceed max_total_file_bytes")


DEFAULT_LIMITS = RuntimeBundleLimits()


@dataclass(frozen=True)
class RuntimeBundleIssue:
    code: str
    message: str
    virtual_path: str | None = None


@dataclass(frozen=True)
class RuntimeBundleVerification:
    """Result of a runtime byte check; all authority fields are permanently false."""

    verified: bool
    manifest: list[Any] | None
    runtime_root: bytes | None
    issues: tuple[RuntimeBundleIssue, ...]
    limitations: tuple[str, ...] = _LIMITATION_TEXT
    state: str = "RUNTIME_BUNDLE_BYTES_ONLY"
    compiler_recomputed: bool = False
    external_evidence_valid: bool = False
    authority: bool = False
    engine_wiring_authority: bool = False
    upload_authority: bool = False
    permit_authority: bool = False
    holdout_access_authority: bool = False
    agent_modification_authority: bool = False


def _fail(code: str, message: str) -> EIRPrebindingError:
    return EIRPrebindingError(code, message)


def _issue_from_error(error: BaseException) -> RuntimeBundleIssue:
    if isinstance(error, EIRPrebindingError):
        return RuntimeBundleIssue(error.code, str(error))
    return RuntimeBundleIssue(RUNTIME_BUNDLE_IO_ERROR, str(error))


def _path_bytes(path: str, label: str) -> bytes:
    if type(path) is not str or not path:
        raise _fail(RUNTIME_BUNDLE_PATH_UNSAFE, f"{label} must be a non-empty text path")
    if "\x00" in path:
        raise _fail(RUNTIME_BUNDLE_PATH_UNSAFE, f"{label} contains NUL")
    try:
        raw = path.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(RUNTIME_BUNDLE_PATH_ENCODING, f"{label} is not strict UTF-8") from exc
    return raw


def _virtual_path(path: str, label: str = "virtual_path", *, max_path_bytes: int = 4096) -> str:
    raw = _path_bytes(path, label)
    if not path.startswith("/") or (path != "/" and path.endswith("/")):
        raise _fail(RUNTIME_BUNDLE_PATH_UNSAFE, f"{label} must be absolute and canonical")
    components = path[1:].split("/") if path != "/" else []
    if any(component in ("", ".", "..") for component in components):
        raise _fail(RUNTIME_BUNDLE_PATH_UNSAFE, f"{label} contains an unsafe component")
    if len(raw) > max_path_bytes:
        raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, f"{label} exceeds the path limit")
    return path


def _host_root(rootfs: os.PathLike[str] | str) -> str:
    try:
        root = os.path.abspath(os.fspath(rootfs))
    except (TypeError, ValueError) as exc:
        raise _fail(RUNTIME_BUNDLE_INVALID_ROOT, "rootfs must be an explicit filesystem path") from exc
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise _fail(RUNTIME_BUNDLE_INVALID_ROOT, f"rootfs cannot be lstat'ed: {exc}") from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        raise _fail(RUNTIME_BUNDLE_ROOT_NOT_DIRECTORY, "rootfs must be a directory, not a symlink or file")
    return root


def _directory_open_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise _fail(RUNTIME_BUNDLE_NO_NOFOLLOW, "the host does not expose safe directory-open flags")
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


def _ensure_same_stat(before: os.stat_result, after: os.stat_result, path: str) -> None:
    if _stat_signature(before) != _stat_signature(after):
        raise _fail(RUNTIME_BUNDLE_RACE_DETECTED, f"filesystem object changed while reading {path}")


def _safe_regular_bytes_at(
    parent_fd: int,
    name: str,
    virtual_path: str,
    initial: os.stat_result,
    limits: RuntimeBundleLimits,
    total_budget: list[int],
) -> tuple[int, bytes, bytes]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _fail(RUNTIME_BUNDLE_NO_NOFOLLOW, "the host does not expose O_NOFOLLOW")
    if initial.st_size > limits.max_file_bytes:
        raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, f"file exceeds the per-file byte limit: {virtual_path}")
    if total_budget[0] + initial.st_size > limits.max_total_file_bytes:
        raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, "rootfs exceeds the total file-byte limit")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    digest = sha256()
    prefix = bytearray()
    count = 0
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise _fail(RUNTIME_BUNDLE_IO_ERROR, f"cannot safely open {virtual_path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise _fail(RUNTIME_BUNDLE_RACE_DETECTED, f"entry changed type while opening {virtual_path}")
        _ensure_same_stat(initial, opened, virtual_path)
        while True:
            remaining_file = limits.max_file_bytes - count
            remaining_total = limits.max_total_file_bytes - total_budget[0] - count
            if remaining_file < 0 or remaining_total < 0:
                raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, f"file exceeded a byte limit: {virtual_path}")
            read_size = min(
                limits.read_chunk_bytes,
                remaining_file + 1,
                remaining_total + 1,
            )
            chunk = os.read(descriptor, read_size)
            if not chunk:
                break
            if len(chunk) > remaining_file:
                raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, f"file grew past the byte limit: {virtual_path}")
            if len(chunk) > remaining_total:
                raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, "rootfs grew past the total file-byte limit")
            count += len(chunk)
            digest.update(chunk)
            if len(prefix) < 2:
                prefix.extend(chunk[: 2 - len(prefix)])
        closed = os.fstat(descriptor)
        _ensure_same_stat(opened, closed, virtual_path)
    except OSError as exc:
        raise _fail(RUNTIME_BUNDLE_IO_ERROR, f"cannot read {virtual_path}: {exc}") from exc
    finally:
        os.close(descriptor)
    final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _ensure_same_stat(initial, final, virtual_path)
    if count != initial.st_size:
        raise _fail(RUNTIME_BUNDLE_RACE_DETECTED, f"file length changed while reading {virtual_path}")
    total_budget[0] += count
    return count, digest.digest(), bytes(prefix)


def _read_symlink_target_at(
    parent_fd: int,
    name: str,
    virtual_path: str,
    initial: os.stat_result,
    max_path_bytes: int,
) -> str:
    try:
        target = os.readlink(name, dir_fd=parent_fd)
    except OSError as exc:
        raise _fail(RUNTIME_BUNDLE_IO_ERROR, f"cannot read symlink {virtual_path}: {exc}") from exc
    if type(target) is not str:
        raise _fail(RUNTIME_BUNDLE_PATH_ENCODING, f"symlink target is not text: {virtual_path}")
    target_bytes = _path_bytes(target, f"symlink target for {virtual_path}")
    if not target_bytes:
        raise _fail(RUNTIME_BUNDLE_PATH_UNSAFE, f"symlink target is empty: {virtual_path}")
    if len(target_bytes) > max_path_bytes:
        raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, f"symlink target exceeds the path limit: {virtual_path}")
    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _ensure_same_stat(initial, after, virtual_path)
    return target


def _entry_for_inode_at(
    parent_fd: int,
    name: str,
    virtual_path: str,
    expected: os.stat_result,
    limits: RuntimeBundleLimits,
    total_budget: list[int],
) -> tuple[list[Any], bytes, int | None]:
    try:
        initial = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise _fail(RUNTIME_BUNDLE_IO_ERROR, f"cannot lstat {virtual_path}: {exc}") from exc
    _ensure_same_stat(expected, initial, virtual_path)
    permissions = stat.S_IMODE(initial.st_mode)
    if stat.S_ISREG(initial.st_mode):
        size, digest, prefix = _safe_regular_bytes_at(
            parent_fd,
            name,
            virtual_path,
            initial,
            limits,
            total_budget,
        )
        return [virtual_path, 1, permissions, size, digest, ""], prefix, None
    if stat.S_ISDIR(initial.st_mode):
        directory_fd: int | None = None
        try:
            directory_fd = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
            opened = os.fstat(directory_fd)
            _ensure_same_stat(initial, opened, virtual_path)
        except EIRPrebindingError:
            if directory_fd is not None:
                os.close(directory_fd)
            raise
        except OSError as exc:
            if directory_fd is not None:
                os.close(directory_fd)
            raise _fail(RUNTIME_BUNDLE_RACE_DETECTED, f"cannot safely open directory {virtual_path}: {exc}") from exc
        return [virtual_path, 2, permissions, 0, ZERO32, ""], b"", directory_fd
    if stat.S_ISLNK(initial.st_mode):
        target = _read_symlink_target_at(parent_fd, name, virtual_path, initial, limits.max_path_bytes)
        encoded = target.encode("utf-8", "strict")
        return [virtual_path, 3, permissions, len(encoded), sha256(encoded).digest(), target], b"", None
    raise _fail(RUNTIME_BUNDLE_SPECIAL_INODE, f"special inode is not allowed: {virtual_path}")


def _child_virtual_path(parent: str, name: str, max_path_bytes: int) -> str:
    raw_name = _path_bytes(name, "filesystem entry name")
    if not raw_name or b"/" in raw_name:
        raise _fail(RUNTIME_BUNDLE_PATH_UNSAFE, "filesystem entry name is not a safe component")
    path = "/" + name if parent == "/" else parent + "/" + name
    return _virtual_path(path, max_path_bytes=max_path_bytes)


def _is_reserved_runtime_path(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in _RESERVED_RUNTIME_PREFIXES)


def _validate_reserved_runtime_paths(entries: Sequence[Sequence[Any]]) -> None:
    for entry in entries:
        if _is_reserved_runtime_path(entry[0]):
            raise _fail(
                RUNTIME_RESERVED_PATH_COLLISION,
                f"runtime manifest collides with a reserved state-3 path: {entry[0]}",
            )


def _open_directory_chain(
    root_fd: int,
    components: Sequence[str],
    expected: os.stat_result,
    virtual_path: str,
) -> int:
    """Reopen a queued parent only through pinned, non-symlink directory FDs."""

    current = os.dup(root_fd)
    try:
        for component in components:
            next_fd = os.open(component, _directory_open_flags(), dir_fd=current)
            os.close(current)
            current = next_fd
        _ensure_same_stat(expected, os.fstat(current), virtual_path)
        return current
    except EIRPrebindingError:
        os.close(current)
        raise
    except OSError as exc:
        os.close(current)
        raise _fail(
            RUNTIME_BUNDLE_RACE_DETECTED,
            f"queued directory changed before traversal at {virtual_path}: {exc}",
        ) from exc


def _collect_rootfs(
    rootfs: os.PathLike[str] | str | int,
    limits: RuntimeBundleLimits,
) -> tuple[list[list[Any]], dict[str, bytes]]:
    limits.validate()
    if type(rootfs) is int:
        try:
            root_expected = os.fstat(rootfs)
            root_fd = os.dup(rootfs)
        except OSError as exc:
            raise _fail(RUNTIME_BUNDLE_RACE_DETECTED, f"cannot duplicate rootfs FD: {exc}") from exc
        if not stat.S_ISDIR(root_expected.st_mode):
            os.close(root_fd)
            raise _fail(RUNTIME_BUNDLE_ROOT_NOT_DIRECTORY, "rootfs FD must name a directory")
    else:
        root = _host_root(rootfs)
        root_expected = os.lstat(root)
        try:
            root_fd = os.open(root, _directory_open_flags())
        except OSError as exc:
            raise _fail(RUNTIME_BUNDLE_RACE_DETECTED, f"cannot safely open rootfs: {exc}") from exc
    try:
        _ensure_same_stat(root_expected, os.fstat(root_fd), "/")
    except BaseException:
        os.close(root_fd)
        raise
    total_budget = [0]
    entries: list[list[Any]] = []
    prefixes: dict[str, bytes] = {}
    pending: list[tuple[str, tuple[str, ...], os.stat_result, os.stat_result]] = [
        ("/", (), root_expected, root_expected)
    ]
    try:
        while pending:
            virtual, components, expected, parent_expected = pending.pop()
            if len(entries) >= limits.max_entries:
                raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, "rootfs exceeds the inode-entry limit")
            if _is_reserved_runtime_path(virtual):
                raise _fail(
                    RUNTIME_RESERVED_PATH_COLLISION,
                    f"runtime rootfs collides with a reserved state-3 path: {virtual}",
                )

            if not components:
                parent_fd = os.dup(root_fd)
                name = "."
            else:
                parent_components = components[:-1]
                parent_virtual = "/" if not parent_components else "/" + "/".join(parent_components)
                parent_fd = _open_directory_chain(
                    root_fd,
                    parent_components,
                    parent_expected,
                    parent_virtual,
                )
                name = components[-1]
            try:
                entry, prefix, directory_fd = _entry_for_inode_at(
                    parent_fd,
                    name,
                    virtual,
                    expected,
                    limits,
                    total_budget,
                )
            finally:
                os.close(parent_fd)
            entries.append(entry)
            if entry[1] == 1:
                prefixes[virtual] = prefix
            if directory_fd is None:
                continue

            try:
                before = os.fstat(directory_fd)
                child_rows: list[
                    tuple[bytes, str, tuple[str, ...], os.stat_result, os.stat_result]
                ] = []
                scan_fd = os.dup(directory_fd)
                try:
                    with os.scandir(scan_fd) as directory:
                        for child in directory:
                            if len(entries) + len(pending) + len(child_rows) >= limits.max_entries:
                                raise _fail(
                                    RUNTIME_BUNDLE_LIMIT_EXCEEDED,
                                    "rootfs exceeds the inode-entry limit",
                                )
                            name = child.name
                            raw_name = _path_bytes(name, "filesystem entry name")
                            child_virtual = _child_virtual_path(virtual, name, limits.max_path_bytes)
                            child_expected = os.stat(
                                name,
                                dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                            child_rows.append(
                                (
                                    raw_name,
                                    child_virtual,
                                    components + (name,),
                                    child_expected,
                                    before,
                                )
                            )
                finally:
                    try:
                        os.close(scan_fd)
                    except OSError:
                        pass
                after = os.fstat(directory_fd)
                _ensure_same_stat(before, after, virtual)
            except EIRPrebindingError:
                raise
            except OSError as exc:
                raise _fail(RUNTIME_BUNDLE_IO_ERROR, f"cannot enumerate {virtual}: {exc}") from exc
            finally:
                os.close(directory_fd)
            for row in sorted(child_rows, reverse=True):
                _, child_virtual, child_components, child_expected, expected_parent = row
                pending.append((child_virtual, child_components, child_expected, expected_parent))
    finally:
        os.close(root_fd)
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    return entries, prefixes


def _resolve_virtual_target(source: str, target: str, max_path_bytes: int = 4096) -> str:
    """Resolve a symlink without letting ``..`` leave the virtual root."""

    if "\x00" in target:
        raise _fail(RUNTIME_BUNDLE_PATH_UNSAFE, f"symlink target contains NUL: {source}")
    components = [] if target.startswith("/") else source.rsplit("/", 1)[0].strip("/").split("/")
    if components == [""]:
        components = []
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not components:
                raise _fail(RUNTIME_BUNDLE_SYMLINK_ESCAPE, f"symlink escapes virtual root: {source}")
            components.pop()
            continue
        components.append(component)
    resolved = "/" + "/".join(components)
    return _virtual_path(resolved, "resolved symlink path", max_path_bytes=max_path_bytes)


def _resolve_symlink_graph(
    entries: Mapping[str, Sequence[Any]],
    limits: RuntimeBundleLimits,
) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for start, entry in entries.items():
        if entry[1] != 3:
            continue
        current = start
        visited: set[str] = set()
        for _ in range(limits.max_symlink_hops):
            if current in visited:
                raise _fail(RUNTIME_BUNDLE_SYMLINK_CYCLE, f"symlink cycle includes {start}")
            visited.add(current)
            current_entry = entries.get(current)
            if current_entry is None:
                raise _fail(RUNTIME_BUNDLE_SYMLINK_TARGET_MISSING, f"symlink target is missing: {start}")
            if current_entry[1] != 3:
                resolved[start] = current
                break
            current = _resolve_virtual_target(current, current_entry[5], limits.max_path_bytes)
            if _is_reserved_runtime_path(current):
                raise _fail(RUNTIME_BUNDLE_SYMLINK_ESCAPE, f"symlink enters a reserved namespace: {start}")
        else:
            raise _fail(RUNTIME_BUNDLE_SYMLINK_CYCLE, f"symlink chain exceeds the hop limit: {start}")
    return resolved


def _compare_entries(
    expected: Sequence[Sequence[Any]],
    actual: Sequence[Sequence[Any]],
    entrypoint_paths: Iterable[str] = (),
) -> list[RuntimeBundleIssue]:
    entrypoint_paths = frozenset(entrypoint_paths)
    expected_by_path = {row[0]: row for row in expected}
    actual_by_path = {row[0]: row for row in actual}
    issues: list[RuntimeBundleIssue] = []
    for path in sorted(set(expected_by_path) - set(actual_by_path), key=lambda value: value.encode("utf-8")):
        issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_MISSING_OBJECT, "manifest object is absent from rootfs", path))
    for path in sorted(set(actual_by_path) - set(expected_by_path), key=lambda value: value.encode("utf-8")):
        issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_UNMANIFESTED_OBJECT, "rootfs object is absent from manifest", path))
    for path in sorted(set(expected_by_path) & set(actual_by_path), key=lambda value: value.encode("utf-8")):
        wanted = expected_by_path[path]
        found = actual_by_path[path]
        if wanted[2] != found[2]:
            issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_PERMISSION_DRIFT, "permission bits differ", path))
        if wanted[1] != found[1]:
            issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_OBJECT_DRIFT, "inode kind differs", path))
            continue
        if wanted[1] == 1:
            if wanted[3] != found[3]:
                code = RUNTIME_BUNDLE_ENTRYPOINT_SIZE_DRIFT if path in entrypoint_paths else RUNTIME_BUNDLE_FILE_SIZE_DRIFT
                issues.append(RuntimeBundleIssue(code, "file size differs", path))
            if wanted[4] != found[4]:
                code = RUNTIME_BUNDLE_ENTRYPOINT_DIGEST_DRIFT if path in entrypoint_paths else RUNTIME_BUNDLE_FILE_DIGEST_DRIFT
                issues.append(RuntimeBundleIssue(code, "file digest differs", path))
        elif wanted[1] == 3:
            if wanted[5] != found[5] or wanted[3] != found[3] or wanted[4] != found[4]:
                issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_SYMLINK_TARGET_DRIFT, "symlink target bytes differ", path))
    return issues


def _entrypoint_issues(
    manifest: Sequence[Any],
    actual: Sequence[Sequence[Any]],
    prefixes: Mapping[str, bytes],
    limits: RuntimeBundleLimits,
) -> list[RuntimeBundleIssue]:
    actual_by_path = {row[0]: row for row in actual}
    issues: list[RuntimeBundleIssue] = []
    for entrypoint in (manifest[1], manifest[2]):
        try:
            final_path = _resolve_entrypoint_path(actual_by_path, entrypoint, limits)
        except EIRPrebindingError as error:
            code = error.code
            if code == RUNTIME_BUNDLE_SYMLINK_CYCLE:
                issue_code = code
            elif code == RUNTIME_BUNDLE_SYMLINK_ESCAPE:
                issue_code = code
            else:
                issue_code = RUNTIME_BUNDLE_ENTRYPOINT_MISSING
            issues.append(RuntimeBundleIssue(issue_code, str(error), entrypoint))
            continue
        final = actual_by_path.get(final_path)
        if final is None:
            issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_ENTRYPOINT_MISSING, "entrypoint is absent", entrypoint))
            continue
        if final[1] != 1:
            issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_ENTRYPOINT_NOT_REGULAR, "entrypoint does not resolve to a regular file", entrypoint))
            continue
        if not final[2] & 0o111:
            issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_ENTRYPOINT_NOT_EXECUTABLE, "entrypoint is not executable", entrypoint))
        prefix = prefixes.get(final_path)
        if prefix is None:
            issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_ENTRYPOINT_MISSING, "entrypoint host path is unavailable", entrypoint))
            continue
        if prefix.startswith(b"#!"):
            issues.append(RuntimeBundleIssue(RUNTIME_BUNDLE_ENTRYPOINT_SHEBANG, "entrypoint begins with a shebang", entrypoint))
    return issues


def _resolve_entrypoint_path(entries: Mapping[str, Sequence[Any]], start: str, limits: RuntimeBundleLimits) -> str:
    current = start
    visited: set[str] = set()
    for _ in range(limits.max_symlink_hops):
        if current in visited:
            raise _fail(RUNTIME_BUNDLE_SYMLINK_CYCLE, "entrypoint symlink cycle is unresolvable")
        visited.add(current)
        entry = entries.get(current)
        if entry is None:
            raise _fail(RUNTIME_BUNDLE_ENTRYPOINT_MISSING, "entrypoint is not present in the rootfs")
        if entry[1] != 3:
            return current
        current = _resolve_virtual_target(current, entry[5], limits.max_path_bytes)
    raise _fail(RUNTIME_BUNDLE_SYMLINK_CYCLE, "entrypoint symlink chain exceeds the hop limit")


def _verify_collected(
    manifest: list[Any],
    actual: list[list[Any]],
    prefixes: Mapping[str, bytes],
    limits: RuntimeBundleLimits,
) -> RuntimeBundleVerification:
    actual_by_path = {row[0]: row for row in actual}
    entrypoint_paths: set[str] = set()
    for entrypoint in (manifest[1], manifest[2]):
        try:
            entrypoint_paths.add(_resolve_entrypoint_path(actual_by_path, entrypoint, limits))
        except EIRPrebindingError:
            entrypoint_paths.add(entrypoint)
    issues = _compare_entries(manifest[4], actual, entrypoint_paths)
    try:
        _resolve_symlink_graph(actual_by_path, limits)
    except EIRPrebindingError as error:
        issues.append(_issue_from_error(error))
    issues.extend(_entrypoint_issues(manifest, actual, prefixes, limits))
    root = toolchain_runtime_root(manifest)
    return RuntimeBundleVerification(
        verified=not issues,
        manifest=manifest,
        runtime_root=root,
        issues=tuple(issues),
    )


def build_toolchain_runtime_manifest(
    rootfs: os.PathLike[str] | str,
    *,
    compiler_entry_path: str,
    extractor_entry_path: str,
    runtime_platform: Sequence[Any],
    limits: RuntimeBundleLimits = DEFAULT_LIMITS,
) -> list[Any]:
    """Enumerate a rootfs mapped to virtual ``/`` and return the exact v2 row."""

    actual, prefixes = _collect_rootfs(rootfs, limits)
    manifest = validate_toolchain_runtime_manifest(
        [1, compiler_entry_path, extractor_entry_path, list(runtime_platform), actual]
    )
    _validate_reserved_runtime_paths(manifest[4])
    report = _verify_collected(manifest, actual, prefixes, limits)
    if not report.verified:
        issue = report.issues[0]
        raise _fail(issue.code, issue.message)
    return manifest


def enumerate_toolchain_runtime_manifest(*args: Any, **kwargs: Any) -> list[Any]:
    """Explicit alias for the rootfs-to-manifest operation."""

    return build_toolchain_runtime_manifest(*args, **kwargs)


def verify_toolchain_runtime_bundle(
    rootfs: os.PathLike[str] | str,
    manifest: Any,
    *,
    limits: RuntimeBundleLimits = DEFAULT_LIMITS,
) -> RuntimeBundleVerification:
    """Compare every rootfs inode and entrypoint byte with a supplied manifest."""

    try:
        limits.validate()
        normalized = validate_toolchain_runtime_manifest(manifest)
        _validate_reserved_runtime_paths(normalized[4])
        if len(normalized[4]) > limits.max_entries:
            raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, "manifest exceeds the inode-entry limit")
        actual, prefixes = _collect_rootfs(rootfs, limits)
        return _verify_collected(normalized, actual, prefixes, limits)
    except (EIRPrebindingError, OSError, ValueError, TypeError) as error:
        return RuntimeBundleVerification(
            verified=False,
            manifest=None,
            runtime_root=None,
            issues=(_issue_from_error(error),),
        )


def verify_toolchain_runtime_bundle_fd(
    rootfs_fd: int,
    manifest: Any,
    *,
    limits: RuntimeBundleLimits = DEFAULT_LIMITS,
) -> RuntimeBundleVerification:
    """Compare a runtime bundle through one retained directory descriptor."""

    try:
        if type(rootfs_fd) is not int:
            raise _fail(RUNTIME_BUNDLE_INVALID_ROOT, "rootfs_fd must be an integer descriptor")
        limits.validate()
        normalized = validate_toolchain_runtime_manifest(manifest)
        _validate_reserved_runtime_paths(normalized[4])
        if len(normalized[4]) > limits.max_entries:
            raise _fail(RUNTIME_BUNDLE_LIMIT_EXCEEDED, "manifest exceeds the inode-entry limit")
        actual, prefixes = _collect_rootfs(rootfs_fd, limits)
        return _verify_collected(normalized, actual, prefixes, limits)
    except (EIRPrebindingError, OSError, ValueError, TypeError) as error:
        return RuntimeBundleVerification(
            verified=False,
            manifest=None,
            runtime_root=None,
            issues=(_issue_from_error(error),),
        )


def assert_toolchain_runtime_bundle(
    rootfs: os.PathLike[str] | str,
    manifest: Any,
    *,
    limits: RuntimeBundleLimits = DEFAULT_LIMITS,
) -> RuntimeBundleVerification:
    """Raise the first stable verifier error, while retaining zero authority."""

    report = verify_toolchain_runtime_bundle(rootfs, manifest, limits=limits)
    if not report.verified:
        issue = report.issues[0]
        raise _fail(issue.code, issue.message)
    return report


def assert_toolchain_runtime_bundle_fd(
    rootfs_fd: int,
    manifest: Any,
    *,
    limits: RuntimeBundleLimits = DEFAULT_LIMITS,
) -> RuntimeBundleVerification:
    """Assert runtime bytes beneath one retained directory descriptor."""

    report = verify_toolchain_runtime_bundle_fd(rootfs_fd, manifest, limits=limits)
    if not report.verified:
        issue = report.issues[0]
        raise _fail(issue.code, issue.message)
    return report


verify_runtime_bundle = verify_toolchain_runtime_bundle


__all__ = [
    "DEFAULT_LIMITS",
    "RUNTIME_BUNDLE_ENTRYPOINT_DIGEST_DRIFT",
    "RUNTIME_BUNDLE_ENTRYPOINT_MISSING",
    "RUNTIME_BUNDLE_ENTRYPOINT_NOT_EXECUTABLE",
    "RUNTIME_BUNDLE_ENTRYPOINT_NOT_REGULAR",
    "RUNTIME_BUNDLE_ENTRYPOINT_SHEBANG",
    "RUNTIME_BUNDLE_ENTRYPOINT_SIZE_DRIFT",
    "RUNTIME_BUNDLE_FILE_DIGEST_DRIFT",
    "RUNTIME_BUNDLE_FILE_SIZE_DRIFT",
    "RUNTIME_BUNDLE_IO_ERROR",
    "RUNTIME_BUNDLE_INVALID_ROOT",
    "RUNTIME_BUNDLE_LIMIT_EXCEEDED",
    "RUNTIME_BUNDLE_MISSING_OBJECT",
    "RUNTIME_BUNDLE_NO_NOFOLLOW",
    "RUNTIME_BUNDLE_OBJECT_DRIFT",
    "RUNTIME_BUNDLE_PATH_ENCODING",
    "RUNTIME_BUNDLE_PATH_UNSAFE",
    "RUNTIME_BUNDLE_PERMISSION_DRIFT",
    "RUNTIME_BUNDLE_RACE_DETECTED",
    "RUNTIME_BUNDLE_ROOT_NOT_DIRECTORY",
    "RUNTIME_BUNDLE_SPECIAL_INODE",
    "RUNTIME_BUNDLE_SYMLINK_CYCLE",
    "RUNTIME_BUNDLE_SYMLINK_ESCAPE",
    "RUNTIME_BUNDLE_SYMLINK_TARGET_DRIFT",
    "RUNTIME_BUNDLE_SYMLINK_TARGET_MISSING",
    "RUNTIME_BUNDLE_UNMANIFESTED_OBJECT",
    "RUNTIME_RESERVED_PATH_COLLISION",
    "SCRIPT_ENTRYPOINT_FORBIDDEN",
    "RuntimeBundleIssue",
    "RuntimeBundleLimits",
    "RuntimeBundleVerification",
    "assert_toolchain_runtime_bundle",
    "assert_toolchain_runtime_bundle_fd",
    "build_toolchain_runtime_manifest",
    "enumerate_toolchain_runtime_manifest",
    "verify_runtime_bundle",
    "verify_toolchain_runtime_bundle",
    "verify_toolchain_runtime_bundle_fd",
]
