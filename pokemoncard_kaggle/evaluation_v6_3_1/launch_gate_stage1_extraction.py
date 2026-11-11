"""Zero-authority diagnostics for the frozen LaunchGateV1 page extraction.

This module implements the corrected extraction boundary from
``V631302_STAGE1_RAW_OBJECT_EXTRACTION_AND_LLVM16_PATH_CUSTODY_ERRATUM_1``.
It preserves the raw Clang-IAS object, writes objcopy's transformed object to a
named discard file, compares the dumped page with the retained raw-object
section, and commits the page with ``renameat2(RENAME_NOREPLACE)``.

``V631302_STAGE1_NATIVE_PID1_FD_CWD_CUSTODY_RECEIPT_ERRATUM_1`` retires
Python-owned process launch from the authoritative extraction path.  The
subprocess implementation remains only as a diagnostic; the public
authoritative-looking entry point fails closed until the native PID-1
custodian and its frozen profile exist.

The module does not freeze the custody controller or decoder toolchain, close
Stage 1, execute the gate, issue a permit, access a holdout, modify an agent,
or authorize an upload.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import subprocess
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final

from .launch_gate_stage1_validation import (
    LaunchGateStage1Issue,
    validate_launch_gate_object_v1,
)


GATE_CODE_SIZE: Final = 874
GATE_OBJECT_SIZE: Final = 8688
GATE_PAGE_SIZE: Final = 4096
GATE_OBJECT_SHA256: Final = bytes.fromhex(
    "c20ea3a183f40c61ca3396771fb92cb948cc603b81e966486996f48bab84a530"
)
GATE_PAGE_SHA256: Final = bytes.fromhex(
    "91fce3ca09e908b9e51d73e887f67a14ba7b5c250180cb613f871666f12277f5"
)
GATE_OBJECT_NAME: Final = "LaunchGateV1.o"
GATE_PAGE_NAME: Final = "LaunchGateV1.page"
GATE_PAGE_TMP_NAME: Final = "LaunchGateV1.page.tmp"
GATE_DISCARD_NAME: Final = "LaunchGateV1.objcopy-discard.o"
GATE_EXTRACTION_DIRECTORY: Final = Path("/work/stage1/gate-extract")
OBJCOPY_PATH: Final = "/usr/bin/objcopy"
ENV_PATH: Final = "/usr/bin/env"

ZERO_AUTHORITY: Final = True
AUTHORITY: Final = False
CALIBRATION_UPLOAD_AUTHORITY: Final = False
PRODUCTION_UPLOAD_AUTHORITY: Final = False
TOOLCHAIN_FREEZE_AUTHORITY: Final = False
TOOLCHAIN_STATE: Final = "DO_NOT_FREEZE_TOOLCHAIN"
CUSTODY_CONTROLLER_PROFILE_STATE: Final = "DO_NOT_FREEZE_CUSTODY_CONTROLLER"
STAGE1_EXTRACTION_CUSTODY_STATE: Final = "OPEN"
AUTHORITATIVE_EXTRACTION_CONTROLLER_AVAILABLE: Final = False

_MAX_OBJECT_BYTES: Final = 1 << 20
_RENAME_NOREPLACE: Final = 1


def gate_extraction_argv_v1() -> tuple[str, ...]:
    """Return the literal corrected GNU extraction argv."""

    return (
        ENV_PATH,
        "-i",
        "PATH=/usr/bin:/bin",
        "LC_ALL=C",
        "LANG=C",
        "TZ=UTC",
        "SOURCE_DATE_EPOCH=0",
        "HOME=/nonexistent",
        "DEBUGINFOD_URLS=",
        OBJCOPY_PATH,
        "--input-target=elf64-x86-64",
        "--output-target=elf64-x86-64",
        "--dump-section",
        f".text.launch_gate_v1={GATE_PAGE_TMP_NAME}",
        GATE_OBJECT_NAME,
        GATE_DISCARD_NAME,
    )


@dataclass(frozen=True, slots=True)
class LaunchGateExtractionEvidenceV1:
    object_sha256: bytes
    page_sha256: bytes
    object_size: int
    page_size: int
    gate_code_size: int


@dataclass(frozen=True, slots=True)
class LaunchGateExtractionValidationResultV1:
    valid: bool
    issues: tuple[LaunchGateStage1Issue, ...]
    evidence: LaunchGateExtractionEvidenceV1 | None = None
    authority: bool = False
    calibration_upload_authority: bool = False
    production_upload_authority: bool = False


@dataclass(frozen=True, slots=True)
class LaunchGateExtractionExecutionV1:
    page: bytes
    evidence: LaunchGateExtractionEvidenceV1
    stdout: bytes
    stderr: bytes
    authority: bool = False


class LaunchGateExtractionError(RuntimeError):
    """A fail-closed extraction execution error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _issue(code: str, message: str) -> LaunchGateExtractionValidationResultV1:
    return LaunchGateExtractionValidationResultV1(
        valid=False,
        issues=(LaunchGateStage1Issue(code, message),),
    )


def validate_launch_gate_extraction_v1(
    object_bytes: bytes,
    extracted_page: bytes,
) -> LaunchGateExtractionValidationResultV1:
    """Validate the exact raw object and independently extracted page."""

    if type(object_bytes) is not bytes or type(extracted_page) is not bytes:
        return _issue("GATE_EXTRACTION_BYTES_REQUIRED", "object and page must be immutable bytes")

    semantic = validate_launch_gate_object_v1(
        object_bytes,
        extracted_page,
        gate_code_size=GATE_CODE_SIZE,
    )
    if not semantic.valid:
        return LaunchGateExtractionValidationResultV1(
            valid=False,
            issues=semantic.issues,
        )

    object_digest = sha256(object_bytes).digest()
    page_digest = sha256(extracted_page).digest()
    if len(object_bytes) != GATE_OBJECT_SIZE:
        return _issue(
            "GATE_EXTRACTION_OBJECT_SIZE_MISMATCH",
            "raw object size differs from the corrected frozen identity",
        )
    if object_digest != GATE_OBJECT_SHA256:
        return _issue(
            "GATE_EXTRACTION_OBJECT_HASH_MISMATCH",
            "object bytes differ from the corrected raw Clang-IAS revision",
        )
    if len(extracted_page) != GATE_PAGE_SIZE:
        return _issue(
            "GATE_EXTRACTION_PAGE_SIZE_MISMATCH",
            "extracted page must be exactly 4096 bytes",
        )
    if page_digest != GATE_PAGE_SHA256:
        return _issue(
            "GATE_EXTRACTION_PAGE_HASH_MISMATCH",
            "extracted page differs from the provisionally pinned page revision",
        )

    evidence = LaunchGateExtractionEvidenceV1(
        object_sha256=object_digest,
        page_sha256=page_digest,
        object_size=len(object_bytes),
        page_size=len(extracted_page),
        gate_code_size=GATE_CODE_SIZE,
    )
    return LaunchGateExtractionValidationResultV1(valid=True, issues=(), evidence=evidence)


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_regular_fd(fd: int, *, label: str, maximum: int) -> tuple[bytes, os.stat_result]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
        raise LaunchGateExtractionError(
            f"{label}_INVALID",
            f"{label} must be one bounded regular file",
        )
    os.lseek(fd, 0, os.SEEK_SET)
    remaining = before.st_size
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(fd, min(remaining, 1 << 16))
        if not chunk:
            raise LaunchGateExtractionError(
                f"{label}_SHORT_READ",
                f"{label} ended before its observed size",
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    after = os.fstat(fd)
    if _stat_identity(before) != _stat_identity(after):
        raise LaunchGateExtractionError(
            f"{label}_CHANGED_DURING_READ",
            f"{label} identity or metadata changed during retained-FD read",
        )
    return b"".join(chunks), after


def _require_owned_regular(
    value: os.stat_result,
    *,
    label: str,
    uid: int,
    gid: int,
    size: int | None = None,
    mode: int | None = None,
) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise LaunchGateExtractionError(f"{label}_INVALID", f"{label} is not a regular file")
    if value.st_uid != uid or value.st_gid != gid:
        raise LaunchGateExtractionError(f"{label}_OWNER_INVALID", f"{label} ownership is not BUID:BGID")
    if value.st_nlink != 1:
        raise LaunchGateExtractionError(f"{label}_LINK_COUNT_INVALID", f"{label} link count is not one")
    if size is not None and value.st_size != size:
        raise LaunchGateExtractionError(f"{label}_SIZE_INVALID", f"{label} size is not {size}")
    if mode is not None and stat.S_IMODE(value.st_mode) != mode:
        raise LaunchGateExtractionError(f"{label}_MODE_INVALID", f"{label} mode is not {mode:04o}")


def _require_bound_directory(path: Path) -> tuple[int, os.stat_result, int, int]:
    if path != GATE_EXTRACTION_DIRECTORY or str(path) != str(GATE_EXTRACTION_DIRECTORY):
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_PATH_INVALID",
            "extraction is bound only to /work/stage1/gate-extract",
        )
    if os.path.realpath(path) != str(GATE_EXTRACTION_DIRECTORY):
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_ALIAS",
            "extraction directory resolves through an alias or symlink",
        )
    try:
        directory_fd = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_INVALID",
            f"cannot open exact extraction directory without following links: {exc}",
        ) from exc
    directory_stat = os.fstat(directory_fd)
    uid = os.geteuid()
    gid = os.getegid()
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or stat.S_IMODE(directory_stat.st_mode) != 0o700
        or directory_stat.st_uid != uid
        or directory_stat.st_gid != gid
    ):
        os.close(directory_fd)
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_PROFILE_INVALID",
            "extraction directory must be an owned real mode-0700 directory",
        )
    try:
        entries = set(os.listdir(directory_fd))
    except OSError as exc:
        os.close(directory_fd)
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_INVALID",
            f"cannot enumerate extraction directory: {exc}",
        ) from exc
    if entries != {GATE_OBJECT_NAME}:
        os.close(directory_fd)
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_NOT_FRESH",
            "pre-extraction directory must contain only LaunchGateV1.o",
        )
    return directory_fd, directory_stat, uid, gid


def _reauthenticate_bound_directory(
    directory_fd: int,
    original: os.stat_result,
    *,
    uid: int,
    gid: int,
) -> None:
    """Require the exact retained directory and pathname to remain bound."""

    retained = os.fstat(directory_fd)
    if (
        retained.st_dev != original.st_dev
        or retained.st_ino != original.st_ino
        or not stat.S_ISDIR(retained.st_mode)
        or stat.S_IMODE(retained.st_mode) != 0o700
        or retained.st_uid != uid
        or retained.st_gid != gid
    ):
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_REPLACED",
            "retained extraction-directory identity or profile changed",
        )
    try:
        path_stat = os.stat(GATE_EXTRACTION_DIRECTORY, follow_symlinks=False)
    except OSError as exc:
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_PATH_INVALID",
            f"cannot reauthenticate exact extraction-directory pathname: {exc}",
        ) from exc
    if (
        not stat.S_ISDIR(path_stat.st_mode)
        or path_stat.st_dev != retained.st_dev
        or path_stat.st_ino != retained.st_ino
    ):
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_PATH_MISMATCH",
            "exact extraction-directory pathname no longer identifies the retained directory",
        )


def _open_regular_nofollow(
    directory_fd: int,
    name: str,
    *,
    label: str,
) -> int:
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise LaunchGateExtractionError(
            f"{label}_OPEN_FAILED",
            f"cannot open {name!r} without following links: {exc}",
        ) from exc


def _rename_noreplace(directory_fd: int) -> None:
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_RENAMEAT2_UNAVAILABLE",
            "renameat2 binding is available only in the pinned Linux/amd64 image",
        )
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_RENAMEAT2_UNAVAILABLE",
            "glibc does not export renameat2",
        )
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd,
        GATE_PAGE_TMP_NAME.encode("ascii"),
        directory_fd,
        GATE_PAGE_NAME.encode("ascii"),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        code = (
            "GATE_EXTRACTION_RENAMEAT2_INCAPABLE"
            if error in {errno.ENOSYS, errno.EINVAL}
            else "GATE_EXTRACTION_PAGE_COMMIT_FAILED"
        )
        raise LaunchGateExtractionError(code, f"renameat2 failed with errno {error}")


def _cleanup_uncommitted(directory_fd: int) -> None:
    failures: list[str] = []
    for name in (GATE_PAGE_TMP_NAME, GATE_DISCARD_NAME):
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            continue
        except OSError as exc:
            failures.append(f"{name}:{exc.errno}")
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        failures.append(f"directory-fsync:{exc.errno}")
    if failures:
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_CLEANUP_FAILED",
            "failed directory is latched for inspection: " + ",".join(failures),
        )


def extract_launch_gate_page_v1(
    build_directory: Path,
    *,
    timeout_seconds: int = 30,
) -> LaunchGateExtractionExecutionV1:
    """Fail closed until the pinned native PID-1 custodian is implemented."""

    del build_directory, timeout_seconds
    raise LaunchGateExtractionError(
        "GATE_EXTRACTION_NATIVE_CUSTODIAN_REQUIRED",
        "Python subprocess launch is retired from the authoritative Stage-1 path",
    )


def diagnostic_extract_launch_gate_page_v1(
    build_directory: Path,
    *,
    timeout_seconds: int = 30,
) -> LaunchGateExtractionExecutionV1:
    """Execute the retired Python route as a zero-authority diagnostic.

    Pinned-image identity, mount provenance, absence of another writable cwd,
    objcopy identity, and the complete decoder toolchain remain separate
    profile obligations.  This function therefore always returns zero-authority
    evidence even when every local check succeeds.
    """

    if not isinstance(build_directory, Path):
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_DIRECTORY_INVALID",
            "build_directory must be pathlib.Path",
        )
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_TIMEOUT_INVALID",
            "timeout_seconds must be a positive integer",
        )

    directory_fd, directory_stat, uid, gid = _require_bound_directory(build_directory)
    committed = False
    completed: subprocess.CompletedProcess[bytes] | None = None
    with ExitStack() as stack:
        stack.callback(os.close, directory_fd)
        try:
            object_fd = _open_regular_nofollow(
                directory_fd,
                GATE_OBJECT_NAME,
                label="GATE_EXTRACTION_OBJECT",
            )
            stack.callback(os.close, object_fd)
            object_bytes, object_stat = _read_regular_fd(
                object_fd,
                label="GATE_EXTRACTION_OBJECT",
                maximum=_MAX_OBJECT_BYTES,
            )
            _require_owned_regular(
                object_stat,
                label="GATE_EXTRACTION_OBJECT",
                uid=uid,
                gid=gid,
                size=GATE_OBJECT_SIZE,
                mode=0o444,
            )
            if sha256(object_bytes).digest() != GATE_OBJECT_SHA256:
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_OBJECT_HASH_MISMATCH",
                    "raw object does not match the corrected Clang-IAS identity",
                )

            old_umask = os.umask(0o077)
            try:
                completed = subprocess.run(
                    gate_extraction_argv_v1(),
                    cwd=str(GATE_EXTRACTION_DIRECTORY),
                    env={},
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=timeout_seconds,
                )
            finally:
                os.umask(old_umask)
            if completed.returncode != 0:
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_COMMAND_FAILED",
                    f"GNU objcopy exited with status {completed.returncode}",
                )
            if completed.stdout or completed.stderr:
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_COMMAND_OUTPUT",
                    "successful GNU objcopy extraction emitted unexpected output",
                )

            _reauthenticate_bound_directory(
                directory_fd,
                directory_stat,
                uid=uid,
                gid=gid,
            )
            if set(os.listdir(directory_fd)) != {
                GATE_OBJECT_NAME,
                GATE_PAGE_TMP_NAME,
                GATE_DISCARD_NAME,
            }:
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_DIRECTORY_CONTAMINATED",
                    "post-objcopy directory entries are not exact",
                )

            object_bytes_after, object_stat_after = _read_regular_fd(
                object_fd,
                label="GATE_EXTRACTION_OBJECT",
                maximum=_MAX_OBJECT_BYTES,
            )
            if (
                _stat_identity(object_stat_after) != _stat_identity(object_stat)
                or object_bytes_after != object_bytes
            ):
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_OBJECT_CHANGED",
                    "retained raw object changed across extraction",
                )
            reopened_object_fd = _open_regular_nofollow(
                directory_fd,
                GATE_OBJECT_NAME,
                label="GATE_EXTRACTION_OBJECT_PATH",
            )
            stack.callback(os.close, reopened_object_fd)
            reopened_object_stat = os.fstat(reopened_object_fd)
            if (
                reopened_object_stat.st_dev != object_stat.st_dev
                or reopened_object_stat.st_ino != object_stat.st_ino
            ):
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_OBJECT_PATH_MISMATCH",
                    "raw-object pathname no longer identifies the retained inode",
                )

            page_fd = _open_regular_nofollow(
                directory_fd,
                GATE_PAGE_TMP_NAME,
                label="GATE_EXTRACTION_PAGE_TMP",
            )
            stack.callback(os.close, page_fd)
            discard_fd = _open_regular_nofollow(
                directory_fd,
                GATE_DISCARD_NAME,
                label="GATE_EXTRACTION_DISCARD",
            )
            stack.callback(os.close, discard_fd)
            page, page_stat = _read_regular_fd(
                page_fd,
                label="GATE_EXTRACTION_PAGE_TMP",
                maximum=GATE_PAGE_SIZE,
            )
            discard_stat = os.fstat(discard_fd)
            _require_owned_regular(
                page_stat,
                label="GATE_EXTRACTION_PAGE_TMP",
                uid=uid,
                gid=gid,
                size=GATE_PAGE_SIZE,
            )
            _require_owned_regular(
                discard_stat,
                label="GATE_EXTRACTION_DISCARD",
                uid=uid,
                gid=gid,
            )
            identities = {
                (object_stat.st_dev, object_stat.st_ino),
                (page_stat.st_dev, page_stat.st_ino),
                (discard_stat.st_dev, discard_stat.st_ino),
            }
            if len(identities) != 3:
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_OUTPUT_IDENTITY_ALIAS",
                    "input, page, and discard output do not have distinct identities",
                )

            validation = validate_launch_gate_extraction_v1(object_bytes, page)
            if not validation.valid or validation.evidence is None:
                issue = validation.issues[0]
                raise LaunchGateExtractionError(issue.code, issue.message)

            os.fchmod(page_fd, 0o444)
            os.fsync(page_fd)
            _rename_noreplace(directory_fd)
            committed = True
            os.fsync(directory_fd)
            os.unlink(GATE_DISCARD_NAME, dir_fd=directory_fd)
            os.fsync(directory_fd)

            final_object_bytes, final_object_stat = _read_regular_fd(
                object_fd,
                label="GATE_EXTRACTION_OBJECT",
                maximum=_MAX_OBJECT_BYTES,
            )
            if (
                _stat_identity(final_object_stat) != _stat_identity(object_stat)
                or final_object_bytes != object_bytes
            ):
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_OBJECT_CHANGED",
                    "raw object changed during page commit",
                )
            final_object_path_fd = _open_regular_nofollow(
                directory_fd,
                GATE_OBJECT_NAME,
                label="GATE_EXTRACTION_FINAL_OBJECT_PATH",
            )
            stack.callback(os.close, final_object_path_fd)
            final_object_path_stat = os.fstat(final_object_path_fd)
            if (
                final_object_path_stat.st_dev != object_stat.st_dev
                or final_object_path_stat.st_ino != object_stat.st_ino
            ):
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_FINAL_OBJECT_PATH_MISMATCH",
                    "final raw-object pathname no longer identifies the retained inode",
                )
            final_page_fd = _open_regular_nofollow(
                directory_fd,
                GATE_PAGE_NAME,
                label="GATE_EXTRACTION_PAGE",
            )
            stack.callback(os.close, final_page_fd)
            final_page, final_page_stat = _read_regular_fd(
                final_page_fd,
                label="GATE_EXTRACTION_PAGE",
                maximum=GATE_PAGE_SIZE,
            )
            _require_owned_regular(
                final_page_stat,
                label="GATE_EXTRACTION_PAGE",
                uid=uid,
                gid=gid,
                size=GATE_PAGE_SIZE,
                mode=0o444,
            )
            if (
                final_page_stat.st_dev != page_stat.st_dev
                or final_page_stat.st_ino != page_stat.st_ino
                or final_page != page
            ):
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_PAGE_COMMIT_MISMATCH",
                    "committed page is not the validated temporary page",
                )
            if set(os.listdir(directory_fd)) != {GATE_OBJECT_NAME, GATE_PAGE_NAME}:
                raise LaunchGateExtractionError(
                    "GATE_EXTRACTION_FINAL_DIRECTORY_INVALID",
                    "final extraction directory entries are not exact",
                )
            _reauthenticate_bound_directory(
                directory_fd,
                directory_stat,
                uid=uid,
                gid=gid,
            )
        except Exception as exc:
            if not committed:
                try:
                    _cleanup_uncommitted(directory_fd)
                except LaunchGateExtractionError as cleanup_exc:
                    raise cleanup_exc from exc
            raise

    assert completed is not None
    return LaunchGateExtractionExecutionV1(
        page=page,
        evidence=validation.evidence,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


__all__ = [
    "AUTHORITY",
    "AUTHORITATIVE_EXTRACTION_CONTROLLER_AVAILABLE",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "CUSTODY_CONTROLLER_PROFILE_STATE",
    "ENV_PATH",
    "GATE_CODE_SIZE",
    "GATE_DISCARD_NAME",
    "GATE_EXTRACTION_DIRECTORY",
    "GATE_OBJECT_NAME",
    "GATE_OBJECT_SHA256",
    "GATE_OBJECT_SIZE",
    "GATE_PAGE_NAME",
    "GATE_PAGE_SHA256",
    "GATE_PAGE_SIZE",
    "GATE_PAGE_TMP_NAME",
    "LaunchGateExtractionError",
    "LaunchGateExtractionEvidenceV1",
    "LaunchGateExtractionExecutionV1",
    "LaunchGateExtractionValidationResultV1",
    "OBJCOPY_PATH",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "TOOLCHAIN_FREEZE_AUTHORITY",
    "TOOLCHAIN_STATE",
    "ZERO_AUTHORITY",
    "diagnostic_extract_launch_gate_page_v1",
    "extract_launch_gate_page_v1",
    "gate_extraction_argv_v1",
    "validate_launch_gate_extraction_v1",
]
