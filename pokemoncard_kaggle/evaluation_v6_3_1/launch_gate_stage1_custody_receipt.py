"""Strict, zero-authority consumer for the Stage-1 custody receipt.

The native ``Stage1ExtractionCustodianV1`` is the only producer of this
receipt.  This module consumes its already-emitted bytes only: it does not
open files, inspect namespaces, launch a process, create a permit, access a
holdout, modify an agent, or authorize an upload.

The diagnostic encoder at the end of the module exists solely to construct
offline test fixtures and recompute the private evidence root.  It must not
be used to create or replace an operational native receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Final, Sequence

from .canonical_trace_codec import canonical_cbor_decode, canonical_cbor_encode


PROTOCOL_ID: Final = 631302
WIRE_VERSION: Final = 2
BODY_FIELD_COUNT: Final = 31
BODY_FIELD_NAMES: Final = (
    "image_id_sha256",
    "custodian_file_identity",
    "pid_namespace_identity",
    "mount_namespace_identity",
    "root_custody_pre",
    "proc_mount_pre",
    "extraction_directory_pre",
    "raw_object_pre",
    "env_executable_identity",
    "objcopy_executable_identity",
    "extraction_argv",
    "extraction_envp",
    "seccomp_policy",
    "pre_census_1",
    "pre_census_2",
    "child_pid",
    "child_starttime",
    "child_security_state",
    "barrier_census_1",
    "barrier_census_2",
    "child_wait_result",
    "root_custody_post",
    "proc_mount_post",
    "extraction_directory_post",
    "raw_object_post",
    "committed_page_identity",
    "final_directory_listing",
    "objcopy_stdout",
    "objcopy_stderr",
    "post_censuses",
    "build_principal",
)
SHA256_SIZE: Final = 32
UINT32_MAX: Final = (1 << 32) - 1
UINT64_MAX: Final = (1 << 64) - 1
MAX_RECEIPT_BYTES: Final = 4 * 1024 * 1024
MAX_MOUNTINFO_LINE_BYTES: Final = 1024 * 1024

S_IFMT: Final = 0o170000
S_IFREG: Final = 0o100000
S_IFDIR: Final = 0o040000
OVERLAYFS_SUPER_MAGIC: Final = 0x794C7630
PROC_SUPER_MAGIC: Final = 0x9FA0
ST_RDONLY: Final = 1

DOMAIN_PREFIX: Final = b"V631302_STAGE1_EXTRACTION_CUSTODY_RECEIPT_V2\x00"
IMAGE_ID_SHA256: Final = bytes.fromhex(
    "38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"
)
RAW_OBJECT_SHA256: Final = bytes.fromhex(
    "c20ea3a183f40c61ca3396771fb92cb948cc603b81e966486996f48bab84a530"
)
PAGE_SHA256: Final = bytes.fromhex(
    "91fce3ca09e908b9e51d73e887f67a14ba7b5c250180cb613f871666f12277f5"
)
EMPTY_BLOB_SHA256: Final = sha256(b"").digest()

ROOT_MOUNT_CLASS_ID: Final = 1
CLD_EXITED: Final = 1
CHILD_PID: Final = 2
CHILD_SECURITY_STATE: Final = (1, 2)

EXTRACTION_ARGV: Final = (
    b"/usr/bin/env",
    b"-i",
    b"PATH=/usr/bin:/bin",
    b"LC_ALL=C",
    b"LANG=C",
    b"TZ=UTC",
    b"SOURCE_DATE_EPOCH=0",
    b"HOME=/nonexistent",
    b"DEBUGINFOD_URLS=",
    b"/usr/bin/objcopy",
    b"--input-target=elf64-x86-64",
    b"--output-target=elf64-x86-64",
    b"--dump-section",
    b".text.launch_gate_v1=LaunchGateV1.page.tmp",
    b"LaunchGateV1.o",
    b"LaunchGateV1.objcopy-discard.o",
)
EXTRACTION_ENVP: Final = (
    b"PATH=/usr/bin:/bin",
    b"LC_ALL=C",
    b"LANG=C",
    b"TZ=UTC",
    b"SOURCE_DATE_EPOCH=0",
    b"HOME=/nonexistent",
    b"DEBUGINFOD_URLS=",
)
SECCOMP_SYSCALLS: Final = (
    56,
    57,
    58,
    80,
    81,
    155,
    165,
    166,
    272,
    308,
    428,
    429,
    430,
    431,
    432,
    433,
    435,
    442,
)
FINAL_OBJECT_NAME: Final = b"LaunchGateV1.o"
FINAL_PAGE_NAME: Final = b"LaunchGateV1.page"

# The controller executable and raw BPF digest were deliberately not supplied
# by the binding.  A structurally valid receipt therefore remains conformance
# evidence only, even when every field below validates.
CUSTODIAN_PROFILE_FROZEN: Final = False
SECCOMP_BPF_PROFILE_FROZEN: Final = False
TOOL_OWNERSHIP_PROFILES_FROZEN: Final = False
RECEIPT_V1_RETIRED_INVALID: Final = True

ZERO_AUTHORITY: Final = True
AUTHORITY: Final = False
CALIBRATION_UPLOAD_AUTHORIZED: Final = False
PRODUCTION_UPLOAD_AUTHORIZED: Final = False
HOLDOUT_ACCESS_AUTHORIZED: Final = False
AGENT_MODIFICATION_AUTHORIZED: Final = False
PERMIT_AUTHORITY: Final = False
NO_UPLOAD: Final = "NO_UPLOAD"


class Stage1CustodyReceiptError(ValueError):
    """One fail-closed structural or semantic receipt error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str) -> None:
    raise Stage1CustodyReceiptError(code, message)


def _sequence(value: object, label: str) -> Sequence[object]:
    if type(value) is not list and type(value) is not tuple:
        _fail("RECEIPT_ARRAY_REQUIRED", f"{label} must be an array")
    return value


def _record(value: object, count: int, label: str) -> Sequence[object]:
    values = _sequence(value, label)
    if len(values) != count:
        _fail("RECEIPT_ARRAY_LENGTH", f"{label} must contain exactly {count} elements")
    return values


def _uint(value: object, label: str, *, maximum: int = UINT64_MAX) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        _fail("RECEIPT_UINT_REQUIRED", f"{label} must be an unsigned integer")
    return value


def _positive_uint(value: object, label: str, *, maximum: int = UINT64_MAX) -> int:
    result = _uint(value, label, maximum=maximum)
    if result == 0:
        _fail("RECEIPT_POSITIVE_UINT_REQUIRED", f"{label} must be positive")
    return result


def _bytes(value: object, label: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        _fail("RECEIPT_BYTES_REQUIRED", f"{label} must be a byte string")
    if length is not None and len(value) != length:
        _fail("RECEIPT_BYTES_LENGTH", f"{label} must contain exactly {length} bytes")
    return value


def _hash(value: object, label: str) -> bytes:
    return _bytes(value, label, SHA256_SIZE)


def _sorted_byte_array(value: object, label: str) -> tuple[bytes, ...]:
    values = _sequence(value, label)
    result = tuple(_bytes(item, f"{label}[{index}]") for index, item in enumerate(values))
    if result != tuple(sorted(result)):
        _fail("RECEIPT_ARRAY_NOT_SORTED", f"{label} is not bytewise sorted")
    if len(set(result)) != len(result):
        _fail("RECEIPT_ARRAY_DUPLICATE", f"{label} contains a duplicate value")
    return result


def _mount_uint(value: bytes, label: str) -> int:
    if not value or any(byte < 0x30 or byte > 0x39 for byte in value):
        _fail("RECEIPT_MOUNT_LINE_SYNTAX", f"{label} is not unsigned decimal")
    result = int(value)
    if result > UINT64_MAX:
        _fail("RECEIPT_MOUNT_LINE_SYNTAX", f"{label} overflows uint64")
    return result


def _decode_mount_bytes(value: bytes, label: str) -> bytes:
    output = bytearray()
    index = 0
    escapes = {b"040": 0x20, b"011": 0x09, b"012": 0x0A, b"134": 0x5C}
    while index < len(value):
        byte = value[index]
        if byte == 0:
            _fail("RECEIPT_MOUNT_LINE_SYNTAX", f"{label} contains NUL")
        if byte != 0x5C:
            output.append(byte)
            index += 1
            continue
        if index + 4 > len(value) or value[index + 1 : index + 4] not in escapes:
            _fail("RECEIPT_MOUNT_LINE_ESCAPE", f"{label} contains a nonstandard escape")
        output.append(escapes[value[index + 1 : index + 4]])
        index += 4
    return bytes(output)


def _mount_options(value: bytes, label: str) -> tuple[bytes, ...]:
    parts = value.split(b",")
    if not parts or any(not part for part in parts):
        _fail("RECEIPT_MOUNT_LINE_SYNTAX", f"{label} contains an empty option")
    decoded = tuple(_decode_mount_bytes(part, label) for part in parts)
    if len(set(decoded)) != len(decoded):
        _fail("RECEIPT_MOUNT_LINE_SYNTAX", f"{label} contains duplicate options")
    return tuple(sorted(decoded))


def _parse_mount_line(value: bytes, label: str) -> tuple[object, ...]:
    if not value or len(value) > MAX_MOUNTINFO_LINE_BYTES or b"\x00" in value or b"\n" in value or b"\r" in value:
        _fail("RECEIPT_MOUNT_LINE_TERMINATOR", f"{label} is not one bounded unterminated line")
    if value.count(b" - ") != 1:
        _fail("RECEIPT_MOUNT_LINE_SYNTAX", f"{label} lacks one exact separator")
    left_raw, right_raw = value.split(b" - ", 1)
    left = left_raw.split(b" ")
    right = right_raw.split(b" ")
    if len(left) < 6 or len(right) != 3 or any(not part for part in left + right):
        _fail("RECEIPT_MOUNT_LINE_SYNTAX", f"{label} has invalid field cardinality")
    device = left[2].split(b":")
    if len(device) != 2:
        _fail("RECEIPT_MOUNT_LINE_SYNTAX", f"{label} has an invalid device field")
    return (
        _mount_uint(left[0], f"{label}.mount_id"),
        _mount_uint(left[1], f"{label}.parent_mount_id"),
        _mount_uint(device[0], f"{label}.device_major"),
        _mount_uint(device[1], f"{label}.device_minor"),
        _decode_mount_bytes(left[3], f"{label}.root"),
        _decode_mount_bytes(left[4], f"{label}.mount_point"),
        _mount_options(left[5], f"{label}.mount_options"),
        tuple(sorted(_decode_mount_bytes(part, f"{label}.optional") for part in left[6:])),
        _decode_mount_bytes(right[0], f"{label}.filesystem"),
        _decode_mount_bytes(right[1], f"{label}.source"),
        _mount_options(right[2], f"{label}.super_options"),
    )


def _one_prefixed_option(options: tuple[bytes, ...], prefix: bytes, label: str) -> bytes:
    matches = tuple(option[len(prefix) :] for option in options if option.startswith(prefix))
    if len(matches) != 1 or not matches[0]:
        _fail("RECEIPT_ROOT_SUPER_OPTIONS", f"{label} is not present exactly once")
    return matches[0]


def _namespace_identity(value: object, label: str) -> tuple[int, ...]:
    values = _record(value, 3, label)
    return tuple(_uint(item, f"{label}[{index}]") for index, item in enumerate(values))


def _object_identity(value: object, label: str) -> tuple[int, ...]:
    values = _record(value, 9, label)
    maxima = (
        UINT64_MAX,
        UINT32_MAX,
        UINT32_MAX,
        UINT64_MAX,
        UINT32_MAX,
        UINT32_MAX,
        UINT32_MAX,
        UINT64_MAX,
        UINT64_MAX,
    )
    return tuple(
        _uint(item, f"{label}[{index}]", maximum=maxima[index])
        for index, item in enumerate(values)
    )


def _object_key(value: tuple[int, ...]) -> tuple[int, int, int, int]:
    return (value[0], value[1], value[2], value[3])


def _owner(value: tuple[int, ...]) -> tuple[int, int]:
    return (value[5], value[6])


def _stable_directory_identity(value: tuple[int, ...]) -> tuple[int, ...]:
    return value[:8]


def _directory_identity(value: object, label: str) -> tuple[object, ...]:
    values = _record(value, 5, label)
    obj = _object_identity(values[0], f"{label}[0]")
    f_type = _uint(values[1], f"{label}[1]")
    fsid0 = _uint(values[2], f"{label}[2]", maximum=UINT32_MAX)
    fsid1 = _uint(values[3], f"{label}[3]", maximum=UINT32_MAX)
    flags = _uint(values[4], f"{label}[4]")
    if obj[4] != (S_IFDIR | 0o700):
        _fail("RECEIPT_DIRECTORY_MODE", f"{label} is not an exact mode-0700 directory")
    if f_type != OVERLAYFS_SUPER_MAGIC or flags & ST_RDONLY:
        _fail("RECEIPT_DIRECTORY_FILESYSTEM", f"{label} is not on writable overlayfs")
    return (obj, f_type, fsid0, fsid1, flags)


def _build_principal(value: object, label: str) -> tuple[int, int]:
    values = _record(value, 2, label)
    return (
        _uint(values[0], f"{label}[0]", maximum=UINT32_MAX),
        _uint(values[1], f"{label}[1]", maximum=UINT32_MAX),
    )


def _file_identity(value: object, label: str) -> tuple[object, ...]:
    values = _record(value, 2, label)
    return (_object_identity(values[0], f"{label}[0]"), _hash(values[1], f"{label}[1]"))


def _require_regular_file(
    value: tuple[object, ...],
    label: str,
    *,
    mode: int | None = None,
    size: int | None = None,
    link_count: int | None = None,
    executable: bool = False,
) -> None:
    obj = value[0]
    if (obj[4] & S_IFMT) != S_IFREG:
        _fail("RECEIPT_FILE_TYPE", f"{label} is not a regular file")
    if mode is not None and obj[4] != (S_IFREG | mode):
        _fail("RECEIPT_FILE_MODE", f"{label} has the wrong permission mode")
    if size is not None and obj[8] != size:
        _fail("RECEIPT_FILE_SIZE", f"{label} has the wrong byte length")
    if link_count is not None and obj[7] != link_count:
        _fail("RECEIPT_FILE_LINK_COUNT", f"{label} has the wrong link count")
    if executable and (obj[4] & 0o111) == 0:
        _fail("RECEIPT_FILE_EXECUTABLE", f"{label} is not executable")
    if executable and obj[4] & 0o6000:
        _fail("RECEIPT_FILE_PRIVILEGED_MODE", f"{label} is setuid or setgid")
    if executable and obj[8] == 0:
        _fail("RECEIPT_FILE_SIZE", f"{label} is empty")


def _mount_info(
    value: object,
    label: str,
    *,
    root: bool = False,
    proc: bool = False,
) -> tuple[object, ...]:
    values = _record(value, 17, label)
    mount_class = _uint(values[0], f"{label}[0]")
    if root and mount_class != ROOT_MOUNT_CLASS_ID:
        _fail("RECEIPT_ROOT_MOUNT_CLASS", "root mount is not ROOT_OVERLAY_WRITABLE_LAYER")
    mount_id = _positive_uint(values[1], f"{label}[1]")
    parent_mount_id = _uint(values[2], f"{label}[2]")
    device_major = _uint(values[3], f"{label}[3]", maximum=UINT32_MAX)
    device_minor = _uint(values[4], f"{label}[4]", maximum=UINT32_MAX)
    decoded_root = _bytes(values[5], f"{label}[5]")
    decoded_point = _bytes(values[6], f"{label}[6]")
    mount_options = _sorted_byte_array(values[7], f"{label}[7]")
    optional_fields = _sorted_byte_array(values[8], f"{label}[8]")
    filesystem = _bytes(values[9], f"{label}[9]")
    source = _bytes(values[10], f"{label}[10]")
    super_options = _sorted_byte_array(values[11], f"{label}[11]")
    statfs_type = _uint(values[12], f"{label}[12]")
    fsid0 = _uint(values[13], f"{label}[13]", maximum=UINT32_MAX)
    fsid1 = _uint(values[14], f"{label}[14]", maximum=UINT32_MAX)
    statfs_flags = _uint(values[15], f"{label}[15]")
    raw_line = _bytes(values[16], f"{label}[16]")
    parsed_line = _parse_mount_line(raw_line, f"{label}[16]")
    if parsed_line != (
        mount_id,
        parent_mount_id,
        device_major,
        device_minor,
        decoded_root,
        decoded_point,
        mount_options,
        optional_fields,
        filesystem,
        source,
        super_options,
    ):
        _fail("RECEIPT_MOUNT_LINE_FIELDS", f"{label} fields do not reproduce its raw line")
    if root and optional_fields != ():
        _fail("RECEIPT_ROOT_OPTIONAL_FIELDS", "root mount has optional mount fields")
    if root:
        if (
            decoded_root != b"/"
            or decoded_point != b"/"
            or filesystem != b"overlay"
            or source != b"overlay"
            or mount_options.count(b"rw") != 1
            or b"ro" in mount_options
            or super_options.count(b"rw") != 1
            or b"ro" in super_options
            or statfs_type != OVERLAYFS_SUPER_MAGIC
            or statfs_flags & ST_RDONLY
        ):
            _fail("RECEIPT_ROOT_MOUNT_PROFILE", "root mount is not the exact writable overlay profile")
        upper = _one_prefixed_option(super_options, b"upperdir=", "upperdir")
        work = _one_prefixed_option(super_options, b"workdir=", "workdir")
        _one_prefixed_option(super_options, b"lowerdir=", "lowerdir")
        if upper == work:
            _fail("RECEIPT_ROOT_SUPER_OPTIONS", "upperdir and workdir are identical")
    if proc:
        if (
            decoded_root != b"/"
            or decoded_point != b"/proc"
            or filesystem != b"proc"
            or source != b"proc"
            or optional_fields != ()
            or statfs_type != PROC_SUPER_MAGIC
        ):
            _fail("RECEIPT_PROC_MOUNT_PROFILE", "proc mount is not the exact namespace-local procfs profile")
    return (
        mount_class,
        mount_id,
        parent_mount_id,
        device_major,
        device_minor,
        decoded_root,
        decoded_point,
        mount_options,
        optional_fields,
        filesystem,
        source,
        super_options,
        statfs_type,
        fsid0,
        fsid1,
        statfs_flags,
        raw_line,
    )


def _root_mount_custody(value: object, label: str) -> tuple[object, ...]:
    values = _record(value, 2, label)
    mount = _mount_info(values[0], f"{label}[0]", root=True)
    root_object = _object_identity(values[1], f"{label}[1]")
    if (root_object[4] & S_IFMT) != S_IFDIR:
        _fail("RECEIPT_ROOT_OBJECT_TYPE", f"{label} root object is not a directory")
    if root_object[:3] != (mount[1], mount[3], mount[4]):
        _fail("RECEIPT_ROOT_OBJECT_MOUNT_BINDING", f"{label} root object is not bound to its mount")
    return (mount, root_object)


def _cwd_identity(value: object, label: str) -> tuple[int, ...]:
    values = _record(value, 4, label)
    return tuple(_uint(item, f"{label}[{index}]") for index, item in enumerate(values))


def _blob_digest(value: object, label: str) -> tuple[int, bytes]:
    values = _record(value, 2, label)
    length = _uint(values[0], f"{label}[0]")
    digest = _hash(values[1], f"{label}[1]")
    if length == 0 and digest != EMPTY_BLOB_SHA256:
        _fail("RECEIPT_EMPTY_BLOB_DIGEST", f"{label} does not hash the empty blob")
    return length, digest


def _seccomp_policy(value: object, label: str) -> tuple[object, ...]:
    values = _record(value, 6, label)
    arch = _uint(values[0], f"{label}[0]")
    x32_bit = _uint(values[1], f"{label}[1]")
    action_kill = _uint(values[2], f"{label}[2]")
    action_allow = _uint(values[3], f"{label}[3]")
    syscalls = tuple(_uint(item, f"{label}[4][{index}]") for index, item in enumerate(_sequence(values[4], f"{label}[4]")))
    raw_bpf_hash = _hash(values[5], f"{label}[5]")
    if (arch, x32_bit, action_kill, action_allow) != (0xC000003E, 0x40000000, 0x80000000, 0x7FFF0000):
        _fail("RECEIPT_SECCOMP_CONSTANT", "seccomp architecture/actions are not frozen values")
    if syscalls != SECCOMP_SYSCALLS:
        _fail("RECEIPT_SECCOMP_SYSCALLS", "seccomp syscall denylist is not the frozen list")
    return (arch, x32_bit, action_kill, action_allow, syscalls, raw_bpf_hash)


def _census(value: object, label: str) -> tuple[object, ...]:
    rows = _sequence(value, label)
    normalized: list[object] = []
    previous_pid: int | None = None
    for row_index, row in enumerate(rows):
        fields = _record(row, 3, f"{label}[{row_index}]")
        pid = _positive_uint(fields[0], f"{label}[{row_index}][0]")
        if previous_pid is not None and pid <= previous_pid:
            _fail("RECEIPT_CENSUS_PID_ORDER", f"{label} PID rows are not ascending")
        previous_pid = pid
        starttime = _positive_uint(fields[1], f"{label}[{row_index}][1]")
        task_rows = _sequence(fields[2], f"{label}[{row_index}][2]")
        normalized_tasks: list[object] = []
        previous_tid: int | None = None
        for task_index, task in enumerate(task_rows):
            task_fields = _record(task, 2, f"{label}[{row_index}][2][{task_index}]")
            tid = _positive_uint(task_fields[0], f"{label}[{row_index}][2][{task_index}][0]")
            if previous_tid is not None and tid <= previous_tid:
                _fail("RECEIPT_CENSUS_TID_ORDER", f"{label} TID rows are not ascending")
            previous_tid = tid
            normalized_tasks.append(
                (tid, _cwd_identity(task_fields[1], f"{label}[{row_index}][2][{task_index}][1]"))
            )
        if not normalized_tasks:
            _fail("RECEIPT_CENSUS_EMPTY_TASKS", f"{label} contains a PID with no tasks")
        normalized.append((pid, starttime, tuple(normalized_tasks)))
    if not normalized:
        _fail("RECEIPT_CENSUS_EMPTY", f"{label} must contain at least one PID")
    return tuple(normalized)


def _expect_census_shape(
    census: tuple[object, ...],
    label: str,
    *,
    pids: tuple[int, ...],
    root_cwd: tuple[int, int, int, int],
    extraction_cwd: tuple[int, ...] | None,
    child_starttime: int | None = None,
) -> None:
    if tuple(row[0] for row in census) != pids:
        _fail("RECEIPT_CENSUS_SHAPE", f"{label} has the wrong PID set")
    for row in census:
        pid, starttime, tasks = row
        expected_tid = pid
        if len(tasks) != 1 or tasks[0][0] != expected_tid:
            _fail("RECEIPT_CENSUS_SHAPE", f"{label} has the wrong task set for PID {pid}")
        if pid == 1 and tasks[0][1] != root_cwd:
            _fail("RECEIPT_CENSUS_CWD", f"{label} PID 1 cwd is not the retained root object")
        if pid == 2:
            if extraction_cwd is None or tasks[0][1] != extraction_cwd:
                _fail("RECEIPT_CENSUS_CWD", f"{label} PID 2 is not in the extraction directory")
            if child_starttime is not None and starttime != child_starttime:
                _fail("RECEIPT_CENSUS_STARTTIME", f"{label} child starttime changed")


def _final_listing(value: object, raw_object: tuple[object, ...], page: tuple[object, ...]) -> tuple[object, ...]:
    rows = _sequence(value, "final_directory_listing")
    if len(rows) != 2:
        _fail("RECEIPT_FINAL_LIST_LENGTH", "final_directory_listing must contain exactly two entries")
    normalized: list[object] = []
    previous_name: bytes | None = None
    for index, row in enumerate(rows):
        fields = _record(row, 2, f"final_directory_listing[{index}]")
        name = _bytes(fields[0], f"final_directory_listing[{index}][0]")
        if previous_name is not None and name <= previous_name:
            _fail("RECEIPT_FINAL_LIST_ORDER", "final_directory_listing names are not strictly sorted")
        previous_name = name
        normalized.append((name, _file_identity(fields[1], f"final_directory_listing[{index}][1]")))
    result = tuple(normalized)
    if result != ((FINAL_OBJECT_NAME, raw_object), (FINAL_PAGE_NAME, page)):
        _fail("RECEIPT_FINAL_LIST_CONTENT", "final directory listing is not the exact committed pair")
    return result


def _validate_body(value: object) -> tuple[object, ...]:
    fields = _record(value, BODY_FIELD_COUNT, "Stage1ExtractionCustodyBodyV2")
    image_id = _bytes(fields[0], "body[0]", SHA256_SIZE)
    if image_id != IMAGE_ID_SHA256:
        _fail("RECEIPT_IMAGE_ID", "image identity is not the frozen image digest")
    custodian = _file_identity(fields[1], "body[1]")
    _require_regular_file(custodian, "body[1]", executable=True)
    pid_namespace = _namespace_identity(fields[2], "body[2]")
    mount_namespace = _namespace_identity(fields[3], "body[3]")
    root_pre = _root_mount_custody(fields[4], "body[4]")
    proc_pre = _mount_info(fields[5], "body[5]", proc=True)
    extraction_pre = _directory_identity(fields[6], "body[6]")
    raw_pre = _file_identity(fields[7], "body[7]")
    _require_regular_file(raw_pre, "body[7]", mode=0o444, size=8688, link_count=1)
    env_exe = _file_identity(fields[8], "body[8]")
    _require_regular_file(env_exe, "body[8]", executable=True)
    objcopy_exe = _file_identity(fields[9], "body[9]")
    _require_regular_file(objcopy_exe, "body[9]", executable=True)
    argv = tuple(
        _bytes(item, f"body[10][{index}]") for index, item in enumerate(_sequence(fields[10], "body[10]"))
    )
    envp = tuple(
        _bytes(item, f"body[11][{index}]") for index, item in enumerate(_sequence(fields[11], "body[11]"))
    )
    if argv != EXTRACTION_ARGV:
        _fail("RECEIPT_ARGV", "extraction argv is not the exact frozen argv")
    if envp != EXTRACTION_ENVP:
        _fail("RECEIPT_ENVP", "extraction envp is not the exact frozen environment")
    seccomp = _seccomp_policy(fields[12], "body[12]")
    pre1 = _census(fields[13], "body[13]")
    pre2 = _census(fields[14], "body[14]")
    child_pid = _uint(fields[15], "body[15]")
    if child_pid != CHILD_PID:
        _fail("RECEIPT_CHILD_PID", "child PID is not 2")
    child_starttime = _positive_uint(fields[16], "body[16]")
    child_security = tuple(_uint(item, f"body[17][{index}]") for index, item in enumerate(_record(fields[17], 2, "body[17]")))
    if child_security != CHILD_SECURITY_STATE:
        _fail("RECEIPT_CHILD_SECURITY", "child security state is not NoNewPrivs=1/seccomp=2")
    barrier1 = _census(fields[18], "body[18]")
    barrier2 = _census(fields[19], "body[19]")
    wait_result = tuple(_uint(item, f"body[20][{index}]") for index, item in enumerate(_record(fields[20], 2, "body[20]")))
    if wait_result != (CLD_EXITED, 0):
        _fail("RECEIPT_WAIT_RESULT", "child did not exit normally with status zero")
    root_post = _root_mount_custody(fields[21], "body[21]")
    proc_post = _mount_info(fields[22], "body[22]", proc=True)
    extraction_post = _directory_identity(fields[23], "body[23]")
    raw_post = _file_identity(fields[24], "body[24]")
    _require_regular_file(raw_post, "body[24]", mode=0o444, size=8688, link_count=1)
    page = _file_identity(fields[25], "body[25]")
    _require_regular_file(page, "body[25]", mode=0o444, size=4096, link_count=1)
    listing = _final_listing(fields[26], raw_post, page)
    stdout = _blob_digest(fields[27], "body[27]")
    stderr = _blob_digest(fields[28], "body[28]")
    post_censuses_values = _record(fields[29], 2, "body[29]")
    post1 = _census(post_censuses_values[0], "body[29][0]")
    post2 = _census(post_censuses_values[1], "body[29][1]")
    build_principal = _build_principal(fields[30], "body[30]")

    if raw_pre[1] != RAW_OBJECT_SHA256 or raw_post[1] != RAW_OBJECT_SHA256:
        _fail("RECEIPT_RAW_OBJECT_HASH", "raw object hash is not the corrected frozen digest")
    if raw_pre != raw_post:
        _fail("RECEIPT_RAW_OBJECT_CHANGED", "raw object identity changed between pre and post")
    if page[1] != PAGE_SHA256:
        _fail("RECEIPT_PAGE_IDENTITY", "committed page identity is not the frozen 4096-byte page")
    if root_pre != root_post or proc_pre != proc_post:
        _fail("RECEIPT_PAIRED_IDENTITY", "paired root custody or proc mount identities are not byte-identical")
    if (
        _stable_directory_identity(extraction_pre[0])
        != _stable_directory_identity(extraction_post[0])
        or extraction_pre[1:] != extraction_post[1:]
    ):
        _fail("RECEIPT_EXTRACTION_DIRECTORY_CHANGED", "stable extraction directory identity changed")
    if pre1 != pre2 or barrier1 != barrier2 or post1 != post2:
        _fail("RECEIPT_PAIRED_CENSUS", "paired census encodings are not byte-identical")

    root_mount = root_pre[0]
    root_object = root_pre[1]
    root_mount_identity = (root_mount[1], root_mount[3], root_mount[4])
    extraction_object = extraction_pre[0]
    if (
        extraction_object[:3] != root_mount_identity
        or extraction_pre[1] != root_mount[12]
        or extraction_pre[2:4] != root_mount[13:15]
        or extraction_pre[4] != root_mount[15]
    ):
        _fail("RECEIPT_EXTRACTION_MOUNT_BINDING", "extraction directory is not bound to the root overlay")
    if _object_key(root_object) == _object_key(extraction_object):
        _fail("RECEIPT_ROOT_EXTRACTION_ALIAS", "root and extraction directory are the same object")
    if _owner(extraction_object) != build_principal or _owner(extraction_post[0]) != build_principal:
        _fail("RECEIPT_DIRECTORY_OWNERSHIP", "extraction directory is not owned by BUID:BGID")
    for label, file_identity in (
        ("raw_pre", raw_pre),
        ("raw_post", raw_post),
        ("page", page),
    ):
        if file_identity[0][:3] != extraction_object[:3]:
            _fail("RECEIPT_FILE_MOUNT_BINDING", f"{label} is not on the retained extraction mount")
        if _owner(file_identity[0]) != build_principal:
            _fail(
                "RECEIPT_FILE_OWNERSHIP",
                f"{label} is not owned by the native-sampled BUID:BGID",
            )
    if _object_key(raw_post[0]) == _object_key(page[0]):
        _fail("RECEIPT_RAW_PAGE_ALIAS", "raw object and committed page are the same object")

    distinct_objects = (
        ("custodian", custodian[0]),
        ("env", env_exe[0]),
        ("objcopy", objcopy_exe[0]),
        ("extraction", extraction_object),
        ("raw", raw_post[0]),
        ("page", page[0]),
    )
    seen_object_keys: dict[tuple[int, int, int, int], str] = {}
    for label, object_identity in distinct_objects:
        key = _object_key(object_identity)
        if key in seen_object_keys:
            _fail(
                "RECEIPT_OBJECT_ALIAS",
                f"{label} aliases {seen_object_keys[key]} by complete object key",
            )
        seen_object_keys[key] = label
    if stdout != (0, EMPTY_BLOB_SHA256) or stderr != (0, EMPTY_BLOB_SHA256):
        _fail("RECEIPT_CHILD_OUTPUT", "objcopy stdout and stderr must both be exactly empty")

    root_cwd = _object_key(root_object)
    extraction_cwd = _object_key(extraction_object)
    _expect_census_shape(
        pre1,
        "body[13]",
        pids=(1,),
        root_cwd=root_cwd,
        extraction_cwd=None,
    )
    _expect_census_shape(
        barrier1,
        "body[18]",
        pids=(1, 2),
        root_cwd=root_cwd,
        extraction_cwd=extraction_cwd,
        child_starttime=child_starttime,
    )
    _expect_census_shape(
        post1,
        "body[29][0]",
        pids=(1,),
        root_cwd=root_cwd,
        extraction_cwd=None,
    )
    if pre1[0][1] != barrier1[0][1] or pre1[0][1] != post1[0][1]:
        _fail("RECEIPT_PID1_STARTTIME", "PID 1 starttime changed across custody checkpoints")
    pid1_cwds = (
        pre1[0][2][0][1],
        barrier1[0][2][0][1],
        post1[0][2][0][1],
    )
    if pid1_cwds[0] != pid1_cwds[1] or pid1_cwds[0] != pid1_cwds[2]:
        _fail("RECEIPT_PID1_CWD_CHANGED", "PID 1 cwd identity changed across custody checkpoints")
    if pid1_cwds[0] == extraction_cwd:
        _fail("RECEIPT_PID1_CWD", "PID 1 cwd equals the extraction directory")

    return (
        image_id,
        custodian,
        pid_namespace,
        mount_namespace,
        root_pre,
        proc_pre,
        extraction_pre,
        raw_pre,
        env_exe,
        objcopy_exe,
        argv,
        envp,
        seccomp,
        pre1,
        pre2,
        child_pid,
        child_starttime,
        child_security,
        barrier1,
        barrier2,
        wait_result,
        root_post,
        proc_post,
        extraction_post,
        raw_post,
        page,
        listing,
        stdout,
        stderr,
        (post1, post2),
        build_principal,
    )


def recompute_stage1_extraction_custody_root(body: object) -> bytes:
    """Recompute the private root over a validated diagnostic body."""

    normalized = _validate_body(body)
    return sha256(DOMAIN_PREFIX + canonical_cbor_encode(normalized)).digest()


@dataclass(frozen=True, slots=True)
class Stage1ExtractionCustodyReceiptResult:
    """Immutable conformance evidence; every authority bit is permanently false."""

    body: tuple[object, ...]
    root: bytes
    canonical_body: bytes
    zero_authority: bool = True
    authority: bool = False
    calibration_upload_authorized: bool = False
    production_upload_authorized: bool = False
    holdout_access_authorized: bool = False
    agent_modification_authorized: bool = False
    permit_authority: bool = False
    custodian_profile_frozen: bool = CUSTODIAN_PROFILE_FROZEN
    seccomp_bpf_profile_frozen: bool = SECCOMP_BPF_PROFILE_FROZEN
    tool_ownership_profiles_frozen: bool = TOOL_OWNERSHIP_PROFILES_FROZEN
    receipt_v1_retired_invalid: bool = RECEIPT_V1_RETIRED_INVALID
    stage1_closure: bool = False
    state: str = NO_UPLOAD


def consume_stage1_extraction_custody_receipt(raw: bytes) -> Stage1ExtractionCustodyReceiptResult:
    """Consume one native receipt and return immutable, zero-authority evidence."""

    if type(raw) is not bytes:
        _fail("RECEIPT_INPUT_BYTES", "receipt input must be bytes")
    if not raw or len(raw) > MAX_RECEIPT_BYTES:
        _fail("RECEIPT_INPUT_LENGTH", "receipt input is empty or exceeds its byte bound")
    try:
        decoded = canonical_cbor_decode(raw)
    except Exception as exc:
        _fail("RECEIPT_CBOR", f"receipt is not strict canonical CBOR: {exc}")
    if type(decoded) is not list:
        _fail("RECEIPT_WRAPPER_ARRAY", "receipt wrapper must be an array")
    wrapper = _record(decoded, 4, "receipt wrapper")
    if _uint(wrapper[0], "wrapper[0]") != PROTOCOL_ID or _uint(wrapper[1], "wrapper[1]") != WIRE_VERSION:
        _fail("RECEIPT_WRAPPER_VERSION", "receipt wrapper protocol or version is not exact")
    body = _validate_body(wrapper[2])
    supplied_root = _hash(wrapper[3], "wrapper[3]")
    canonical_body = canonical_cbor_encode(body)
    expected_root = sha256(DOMAIN_PREFIX + canonical_body).digest()
    if supplied_root != expected_root:
        _fail("RECEIPT_ROOT_MISMATCH", "receipt root does not match the canonical body")
    if canonical_cbor_encode((PROTOCOL_ID, WIRE_VERSION, body, supplied_root)) != raw:
        _fail("RECEIPT_NONCANONICAL_WRAPPER", "receipt wrapper does not re-encode byte-identically")
    return Stage1ExtractionCustodyReceiptResult(body, supplied_root, canonical_body)


def consume_stage1_custody_receipt(raw: bytes) -> Stage1ExtractionCustodyReceiptResult:
    """Compatibility spelling for the diagnostic receipt consumer."""

    return consume_stage1_extraction_custody_receipt(raw)


def validate_stage1_extraction_custody_receipt(raw: bytes) -> Stage1ExtractionCustodyReceiptResult:
    """Validate one receipt without granting any operational authority."""

    return consume_stage1_extraction_custody_receipt(raw)


def diagnostic_encode_fixture_receipt(body: object) -> bytes:
    """Encode a test-only fixture; never use this to emit an operational receipt."""

    normalized = _validate_body(body)
    root = sha256(DOMAIN_PREFIX + canonical_cbor_encode(normalized)).digest()
    return canonical_cbor_encode((PROTOCOL_ID, WIRE_VERSION, normalized, root))


__all__ = [
    "AUTHORITY",
    "BODY_FIELD_COUNT",
    "BODY_FIELD_NAMES",
    "CALIBRATION_UPLOAD_AUTHORIZED",
    "CHILD_PID",
    "CUSTODIAN_PROFILE_FROZEN",
    "DOMAIN_PREFIX",
    "EMPTY_BLOB_SHA256",
    "EXTRACTION_ARGV",
    "EXTRACTION_ENVP",
    "HOLDOUT_ACCESS_AUTHORIZED",
    "IMAGE_ID_SHA256",
    "NO_UPLOAD",
    "PAGE_SHA256",
    "PROTOCOL_ID",
    "PRODUCTION_UPLOAD_AUTHORIZED",
    "RAW_OBJECT_SHA256",
    "RECEIPT_V1_RETIRED_INVALID",
    "SECCOMP_BPF_PROFILE_FROZEN",
    "SECCOMP_SYSCALLS",
    "Stage1CustodyReceiptError",
    "Stage1ExtractionCustodyReceiptResult",
    "TOOL_OWNERSHIP_PROFILES_FROZEN",
    "WIRE_VERSION",
    "ZERO_AUTHORITY",
    "consume_stage1_custody_receipt",
    "consume_stage1_extraction_custody_receipt",
    "diagnostic_encode_fixture_receipt",
    "recompute_stage1_extraction_custody_root",
    "validate_stage1_extraction_custody_receipt",
]
