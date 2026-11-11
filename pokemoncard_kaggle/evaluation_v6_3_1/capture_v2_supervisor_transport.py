"""Private zero-authority image substrate for the Capture V2 supervisor.

Only the reviewed-source open and sealed-memfd staging checkpoints exist here.
The former Python ``fork``/``ctypes`` child launcher was retired because it
could not satisfy the binding's post-clone execution rules. LaunchGateV1 is not
implemented or callable from this module. This code cannot assemble Capture
V2, issue a permit, modify an agent, or authorize any upload.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
from hashlib import sha256
import os
import platform
import stat
from typing import Final

import fcntl


PROTOCOL_ID: Final = 631302
SUPERVISOR_TRANSPORT_VERSION: Final = 1
SUPERVISOR_MEMFD_NAME: Final = "v631302-native-supervisor"
SUPERVISOR_MAX_BYTES: Final = 64 * 1024 * 1024
SUPERVISOR_COPY_CHUNK_BYTES: Final = 1024 * 1024

ZERO_AUTHORITY: Final = True
AUTHORITY: Final = False
UPLOAD_AUTHORITY: Final = False
CALIBRATION_UPLOAD_AUTHORITY: Final = False
PRODUCTION_UPLOAD_AUTHORITY: Final = False
HOLDOUT_ACCESS_AUTHORITY: Final = False
AGENT_MODIFICATION_AUTHORITY: Final = False
LAUNCH_GATE_V1_IMPLEMENTED: Final = False

_SYS_OPENAT2_X86_64: Final = 437
_RESOLVE_NO_XDEV: Final = 0x01
_RESOLVE_NO_MAGICLINKS: Final = 0x02
_RESOLVE_NO_SYMLINKS: Final = 0x04
_RESOLVE_BENEATH: Final = 0x08
_OPEN_RESOLVE_FLAGS: Final = (
    _RESOLVE_NO_XDEV
    | _RESOLVE_NO_MAGICLINKS
    | _RESOLVE_NO_SYMLINKS
    | _RESOLVE_BENEATH
)

_MFD_CLOEXEC: Final = getattr(os, "MFD_CLOEXEC", 0x0001)
_MFD_ALLOW_SEALING: Final = getattr(os, "MFD_ALLOW_SEALING", 0x0002)
_MFD_EXEC: Final = getattr(os, "MFD_EXEC", 0x0010)

_F_ADD_SEALS: Final = getattr(fcntl, "F_ADD_SEALS", 1033)
_F_GET_SEALS: Final = getattr(fcntl, "F_GET_SEALS", 1034)
_F_SEAL_SEAL: Final = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
_F_SEAL_SHRINK: Final = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
_F_SEAL_GROW: Final = getattr(fcntl, "F_SEAL_GROW", 0x0004)
_F_SEAL_WRITE: Final = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
_REQUIRED_SEALS: Final = (
    _F_SEAL_WRITE | _F_SEAL_GROW | _F_SEAL_SHRINK | _F_SEAL_SEAL
)


class SupervisorTransportError(RuntimeError):
    pass


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


@dataclass(slots=True)
class _SealedSupervisorImage:
    fd: int
    sha256_digest: bytes
    size: int
    device: int
    inode: int
    seals: int
    used_mfd_exec: bool
    _closed: bool = False

    def fileno(self) -> int:
        if self._closed:
            raise SupervisorTransportError("sealed supervisor image is closed")
        return self.fd

    def close(self) -> None:
        if not self._closed:
            os.close(self.fd)
            self._closed = True

    def __enter__(self) -> _SealedSupervisorImage:
        self.fileno()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _require_linux_amd64() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SupervisorTransportError(
            "supervisor transport requires a capable Linux/amd64 runtime"
        )


def _canonical_relative_path(value: str) -> bytes:
    if type(value) is not str or not value or "\x00" in value or "\\" in value:
        raise SupervisorTransportError("supervisor path is not canonical text")
    if value.startswith("/") or value.endswith("/"):
        raise SupervisorTransportError("supervisor path must be relative")
    if any(part in ("", ".", "..") for part in value.split("/")):
        raise SupervisorTransportError("supervisor path is not canonical")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise SupervisorTransportError("supervisor path is not valid UTF-8") from exc
    if len(encoded) > 4096:
        raise SupervisorTransportError("supervisor path exceeds PATH_MAX")
    return encoded


def _validate_expected_digest(expected_review_digest: bytes) -> bytes:
    if type(expected_review_digest) is not bytes or len(expected_review_digest) != 32:
        raise SupervisorTransportError("expected supervisor digest must be 32 bytes")
    return expected_review_digest


def _fd_flags(fd: int) -> int:
    try:
        return int(fcntl.fcntl(fd, fcntl.F_GETFD))
    except OSError as exc:
        raise SupervisorTransportError("cannot inspect descriptor flags") from exc


def _require_directory_fd(directory_fd: int) -> None:
    if type(directory_fd) is not int or directory_fd < 0:
        raise SupervisorTransportError("supervisor directory FD is invalid")
    try:
        metadata = os.fstat(directory_fd)
    except OSError as exc:
        raise SupervisorTransportError("supervisor directory FD cannot be inspected") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise SupervisorTransportError("supervisor root FD is not a directory")
    if not (_fd_flags(directory_fd) & fcntl.FD_CLOEXEC):
        raise SupervisorTransportError("supervisor root FD is not CLOEXEC")


def _open_reviewed_supervisor(directory_fd: int, relative_path: str) -> int:
    """Open one source object without following links or crossing mounts."""

    _require_linux_amd64()
    _require_directory_fd(directory_fd)
    path = _canonical_relative_path(relative_path)
    how = _OpenHow(
        flags=os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode=0,
        resolve=_OPEN_RESOLVE_FLAGS,
    )
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    result = syscall(
        ctypes.c_long(_SYS_OPENAT2_X86_64),
        ctypes.c_int(directory_fd),
        ctypes.c_char_p(path),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if result < 0:
        error = ctypes.get_errno()
        raise SupervisorTransportError(
            f"openat2 rejected the reviewed supervisor: errno={error}"
        ) from OSError(error, os.strerror(error))
    fd = int(result)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SupervisorTransportError("reviewed supervisor is not a regular file")
        if not (_fd_flags(fd) & fcntl.FD_CLOEXEC):
            raise SupervisorTransportError("reviewed supervisor FD is not CLOEXEC")
        if metadata.st_size <= 0 or metadata.st_size > SUPERVISOR_MAX_BYTES:
            raise SupervisorTransportError("reviewed supervisor size is outside bounds")
        return fd
    except Exception:
        os.close(fd)
        raise


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_exact_fd(fd: int, size: int) -> bytes:
    digest = sha256()
    offset = 0
    while offset < size:
        requested = min(SUPERVISOR_COPY_CHUNK_BYTES, size - offset)
        try:
            chunk = os.pread(fd, requested, offset)
        except OSError as exc:
            raise SupervisorTransportError("supervisor FD read failed") from exc
        if len(chunk) != requested:
            raise SupervisorTransportError("supervisor FD changed or became truncated")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(fd, 1, size):
        raise SupervisorTransportError("supervisor FD grew during hashing")
    return digest.digest()


def _create_executable_memfd() -> tuple[int, bool]:
    if not hasattr(os, "memfd_create"):
        raise SupervisorTransportError("memfd_create is unavailable")
    base_flags = _MFD_CLOEXEC | _MFD_ALLOW_SEALING
    try:
        return os.memfd_create(SUPERVISOR_MEMFD_NAME, base_flags | _MFD_EXEC), True
    except OSError as exc:
        if exc.errno != errno.EINVAL:
            raise SupervisorTransportError("executable memfd creation failed") from exc
    try:
        return os.memfd_create(SUPERVISOR_MEMFD_NAME, base_flags), False
    except OSError as exc:
        raise SupervisorTransportError("compatible executable memfd creation failed") from exc


def _copy_exact(source_fd: int, destination_fd: int, size: int) -> None:
    offset = 0
    while offset < size:
        requested = min(SUPERVISOR_COPY_CHUNK_BYTES, size - offset)
        try:
            chunk = os.pread(source_fd, requested, offset)
        except OSError as exc:
            raise SupervisorTransportError("supervisor source copy read failed") from exc
        if len(chunk) != requested:
            raise SupervisorTransportError("supervisor source changed during copy")
        written = 0
        while written < len(chunk):
            try:
                count = os.pwrite(destination_fd, chunk[written:], offset + written)
            except OSError as exc:
                raise SupervisorTransportError("supervisor memfd copy write failed") from exc
            if count <= 0:
                raise SupervisorTransportError("supervisor memfd copy made no progress")
            written += count
        offset += len(chunk)


def _stage_supervisor_from_open_fd(
    source_fd: int,
    expected_review_digest: bytes,
    /,
) -> _SealedSupervisorImage:
    """Copy one already-open reviewed object into a sealed executable memfd."""

    _require_linux_amd64()
    expected = _validate_expected_digest(expected_review_digest)
    if type(source_fd) is not int or source_fd < 0:
        raise SupervisorTransportError("reviewed supervisor FD is invalid")
    try:
        before = os.fstat(source_fd)
    except OSError as exc:
        raise SupervisorTransportError("reviewed supervisor FD cannot be inspected") from exc
    if not stat.S_ISREG(before.st_mode):
        raise SupervisorTransportError("reviewed supervisor FD is not regular")
    if not (_fd_flags(source_fd) & fcntl.FD_CLOEXEC):
        raise SupervisorTransportError("reviewed supervisor FD is not CLOEXEC")
    if before.st_size <= 0 or before.st_size > SUPERVISOR_MAX_BYTES:
        raise SupervisorTransportError("reviewed supervisor size is outside bounds")

    source_digest = _hash_exact_fd(source_fd, before.st_size)
    memfd, used_mfd_exec = _create_executable_memfd()
    try:
        if not (_fd_flags(memfd) & fcntl.FD_CLOEXEC):
            raise SupervisorTransportError("supervisor memfd is not CLOEXEC")
        _copy_exact(source_fd, memfd, before.st_size)
        copied = os.fstat(memfd)
        if copied.st_size != before.st_size:
            raise SupervisorTransportError("copied supervisor size differs")
        copied_digest = _hash_exact_fd(memfd, copied.st_size)

        after = os.fstat(source_fd)
        if _metadata_identity(after) != _metadata_identity(before):
            raise SupervisorTransportError("reviewed supervisor changed during staging")
        if _hash_exact_fd(source_fd, after.st_size) != source_digest:
            raise SupervisorTransportError("reviewed supervisor digest changed during staging")

        os.fchmod(memfd, 0o500)
        try:
            fcntl.fcntl(memfd, _F_ADD_SEALS, _REQUIRED_SEALS)
            seals = int(fcntl.fcntl(memfd, _F_GET_SEALS))
        except OSError as exc:
            raise SupervisorTransportError("supervisor memfd sealing failed") from exc
        if seals & _REQUIRED_SEALS != _REQUIRED_SEALS:
            raise SupervisorTransportError("supervisor memfd lacks required seals")
        sealed = os.fstat(memfd)
        if sealed.st_size != before.st_size or stat.S_IMODE(sealed.st_mode) != 0o500:
            raise SupervisorTransportError("sealed supervisor metadata differs")
        sealed_digest = _hash_exact_fd(memfd, sealed.st_size)
        if not (
            source_digest == copied_digest == sealed_digest == expected
        ):
            raise SupervisorTransportError("supervisor digest chain does not match review")
        return _SealedSupervisorImage(
            fd=memfd,
            sha256_digest=sealed_digest,
            size=sealed.st_size,
            device=sealed.st_dev,
            inode=sealed.st_ino,
            seals=seals,
            used_mfd_exec=used_mfd_exec,
        )
    except Exception:
        os.close(memfd)
        raise


def _open_and_stage_reviewed_supervisor(
    directory_fd: int,
    relative_path: str,
    expected_review_digest: bytes,
    /,
) -> _SealedSupervisorImage:
    source_fd = _open_reviewed_supervisor(directory_fd, relative_path)
    try:
        return _stage_supervisor_from_open_fd(source_fd, expected_review_digest)
    finally:
        os.close(source_fd)


__all__ = [
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "HOLDOUT_ACCESS_AUTHORITY",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "UPLOAD_AUTHORITY",
    "ZERO_AUTHORITY",
]
