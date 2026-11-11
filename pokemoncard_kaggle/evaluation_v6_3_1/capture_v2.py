"""Pure, zero-authority RAW_COLLECTOR_CAPTURE_V2 validation and roots.

This module validates only the complete arrays-only canonical-CBOR capture
record specified by Amendment 8 as corrected by Amendment 10.  It performs no
filesystem access, process execution, descriptor inspection, namespace work,
ptrace, permit issuance, upload, holdout access, or agent behaviour.  Facts
that require observing a live process remain explicit external-evidence
prerequisites and can never be promoted by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .capture_namespace_v1 import (
    CAPTURE_NAMESPACE_MANIFEST_V1,
    CLANG_CPP_IMPLEMENTATION,
    COLLECTOR_EXECUTABLE,
    ELF_INTERPRETER,
    RUNTIME_DEPENDENCY,
    derive_capture_namespace_roots_v1,
    validate_capture_namespace_manifest_v1,
)
from .eir_prebinding import EIRPrebindingError, eir_canonical_cbor_decode, eir_canonical_cbor_encode


PROTOCOL_ID = 631302
RAW_COLLECTOR_CAPTURE_V2 = 2
ACTUAL_COLLECTOR_INVOCATION_V2 = 2
CLANG_RUNTIME_BINDING_V2 = 2
COLLECTOR_EXECUTION_RECORD_V1 = 1

RAW_COLLECTOR_CAPTURE_MAX_BYTES_V1 = 67_108_864
COLLECTOR_RECEIPT_STREAM_MAX_BYTES_V1 = 16_777_216
RECEIPT_MAGIC_V1 = b"V631CR01"

OBSERVATION_PRES_DRIVER = 0
OBSERVATION_DRIVER = 1
OBSERVATION_CC1 = 2
OBSERVATION_POST_CC1 = 3

RUNTIME_OBSERVATION_EXEC_PROC_EXE = 1
RUNTIME_OBSERVATION_MMAP_FD_PROT_EXEC = 2
RUNTIME_OBSERVATION_PROC_MAP_FILES_PROT_EXEC = 3
PROT_EXEC = 4

RECEIPT_CHANNEL_BIND = 1
RECEIPT_PHASE_TRANSITION = 2
RECEIPT_DRIVER_ARGV = 3
RECEIPT_CC1_ARGV = 4
RECEIPT_FINAL = 5

DS_ACTUAL_OPEN_TRACE = b"V631302_ACTUAL_OPEN_TRACE_V1"
DS_INVOCATION = b"V631302_ACTUAL_COLLECTOR_INVOCATION_V2"
DS_RUNTIME_OBSERVATION = b"V631302_CLANG_RUNTIME_OBSERVATION_V2"
DS_RUNTIME_CLOSURE = b"V631302_CLANG_RUNTIME_CLOSURE_V2"
DS_HARNESS_CLOSURE = b"V631302_CAPTURE_HARNESS_CLOSURE_V1"
DS_CAPTURE_ROOT = b"V631302_RAW_COLLECTOR_CAPTURE_V2"

M0_DIAGNOSTIC_INVENTORY_INCOMPLETE = "M0_DIAGNOSTIC_INVENTORY_INCOMPLETE"

ZERO_AUTHORITY = True
AUTHORITY = False
ENGINE_WIRING_AUTHORITY = False
UPLOAD_AUTHORITY = False
PERMIT_AUTHORITY = False
HOLDOUT_ACCESS_AUTHORITY = False
AGENT_MODIFICATION_AUTHORITY = False
CALIBRATION_UPLOAD_AUTHORITY = False
PRODUCTION_UPLOAD_AUTHORITY = False
SEALED_HOLDOUT_ACCESS_AUTHORITY = False

EXTERNAL_EVIDENCE_PREREQUISITES = (
    "NATIVE_LINUX_AMD64_EXECUTION",
    "SEALED_NAMESPACE_IMMUTABILITY_AND_MOUNT_POLICY",
    "ACTUAL_EXECVE_ARGV_CWD_AND_EMPTY_ENVIRONMENT",
    "RETAINED_ORIGINAL_INPUT_FD_CUSTODY",
    "PTRACE_OR_EQUIVALENT_OPEN_TRACE_COMPLETENESS",
    "INDEPENDENT_DRIVER_CC1_MANIFEST_AND_PATH_RESOLUTION_DERIVATION",
    "RECEIPT_FD_FLAGS_AND_PIPE_IDENTITY",
    "SINGLE_WRITE_PHASE_ATOMICITY_AND_CHANNEL_SEPARATION",
    "CONCURRENT_DRAIN_LIMITS_AND_COMPLETE_CHANNEL_EOF",
    "SINGLE_THREAD_EXECUTION_UNTIL_FINAL_RECEIPT",
    "ACTUAL_PT_INTERP_AND_ELF_METADATA_DERIVATION",
    "ELF_SONAME_BUILD_ID_AND_RUNTIME_MAPPING_OBSERVATION",
)


@dataclass(frozen=True)
class CaptureV2Roots:
    """All byte-recomputable Capture V2 roots, permanently without authority."""

    source_root: bytes
    runtime_root: bytes
    execution_namespace_root: bytes
    actual_open_trace_root: bytes
    invocation_root: bytes
    runtime_observation_root: bytes
    clang_runtime_closure_root: bytes
    capture_harness_closure_root: bytes
    raw_collector_capture_root: bytes
    state: str = "RAW_COLLECTOR_CAPTURE_V2_BYTES_ONLY"
    authority: bool = AUTHORITY
    engine_wiring_authority: bool = ENGINE_WIRING_AUTHORITY
    upload_authority: bool = UPLOAD_AUTHORITY
    permit_authority: bool = PERMIT_AUTHORITY
    holdout_access_authority: bool = HOLDOUT_ACCESS_AUTHORITY
    agent_modification_authority: bool = AGENT_MODIFICATION_AUTHORITY
    calibration_upload_authority: bool = CALIBRATION_UPLOAD_AUTHORITY
    production_upload_authority: bool = PRODUCTION_UPLOAD_AUTHORITY
    sealed_holdout_access_authority: bool = SEALED_HOLDOUT_ACCESS_AUTHORITY
    external_evidence_prerequisites: tuple[str, ...] = EXTERNAL_EVIDENCE_PREREQUISITES


def _fail(message: str) -> EIRPrebindingError:
    return EIRPrebindingError(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, message)


def _list(value: Any, label: str, width: int | None = None) -> list[Any]:
    if type(value) is not list:
        raise _fail(f"{label} must be a CBOR array")
    if width is not None and len(value) != width:
        raise _fail(f"{label} must contain exactly {width} fields")
    return value


def _uint(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise _fail(f"{label} must be uint64")
    if positive and value == 0:
        raise _fail(f"{label} must be positive")
    return value


def _exact_uint(value: Any, expected: int, label: str) -> int:
    checked = _uint(value, label)
    if checked != expected:
        raise _fail(f"{label} must be exactly {expected}")
    return checked


def _bstr(value: Any, label: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise _fail(f"{label} must be a byte string")
    if length is not None and len(value) != length:
        raise _fail(f"{label} must be exactly {length} bytes")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or "\x00" in value:
        raise _fail(f"{label} must be NUL-free text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(f"{label} must be valid UTF-8") from exc
    return value


def _relative_path(value: Any, label: str) -> str:
    path = _text(value, label)
    if not path:
        raise _fail(f"{label} must be nonempty")
    if path.startswith("/") or "\\" in path:
        raise _fail(f"{label} must be a relative slash-separated path")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise _fail(f"{label} has noncanonical path components")
    return path


def _arrays_only(value: Any, label: str) -> None:
    if type(value) is list:
        for index, item in enumerate(value):
            _arrays_only(item, f"{label}[{index}]")
        return
    if type(value) is bool or value is None or type(value) is float:
        raise _fail(f"{label} contains a forbidden CBOR scalar")
    if type(value) is int:
        _uint(value, label)
        return
    if type(value) is bytes:
        return
    if type(value) is str:
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise _fail(f"{label} must be valid UTF-8") from exc
        return
    raise _fail(f"{label} contains a forbidden value")


def _root(domain: bytes, *fields: Any) -> bytes:
    return sha256(eir_canonical_cbor_encode([domain, *fields])).digest()


def _row_sort_key(row: list[Any]) -> bytes:
    return eir_canonical_cbor_encode(row)


def _strict_cbor_order(rows: list[Any], label: str) -> None:
    previous: bytes | None = None
    for index, row in enumerate(rows):
        encoded = _row_sort_key(row)
        if previous is not None and encoded <= previous:
            raise _fail(f"{label} must be strict canonical-CBOR sorted and duplicate-free at {index}")
        previous = encoded


def _namespace(value: Any) -> tuple[list[Any], dict[str, list[Any]]]:
    record = _list(value, "sealed_namespace_record", 4)
    manifest = validate_capture_namespace_manifest_v1(record[0])
    roots = derive_capture_namespace_roots_v1(manifest)
    for label, claim, expected in (
        ("source_root", record[1], roots.source_root),
        ("runtime_root", record[2], roots.runtime_root),
        ("execution_namespace_root", record[3], roots.execution_namespace_root),
    ):
        if _bstr(claim, label, 32) != expected:
            raise _fail(f"sealed namespace {label} does not recompute")
    return record, {row[0]: row for row in manifest[4]}


def _component_record(value: Any, label: str) -> list[Any]:
    row = _list(value, label, 3)
    _uint(row[0], f"{label}.byte_length", positive=True)
    _bstr(row[1], f"{label}.sha256", 32)
    build_id = _text(row[2], f"{label}.build_id")
    if len(build_id) % 2 or any(character not in "0123456789abcdef" for character in build_id):
        raise _fail(f"{label}.build_id must be canonical lowercase hexadecimal text")
    try:
        raw_build_id = bytes.fromhex(build_id)
    except ValueError as exc:
        raise _fail(f"{label}.build_id must be canonical lowercase hexadecimal text") from exc
    if not raw_build_id or raw_build_id.hex() != build_id:
        raise _fail(f"{label}.build_id must be canonical lowercase hexadecimal text")
    return row


def _argv(value: Any, label: str) -> list[str]:
    argv = _list(value, label)
    if not argv:
        raise _fail(f"{label} must be nonempty")
    return [_text(item, f"{label}[{index}]") for index, item in enumerate(argv)]


def _actual_open_rows(value: Any, namespace_rows: dict[str, list[Any]]) -> list[list[Any]]:
    rows = _list(value, "actual_open_rows")
    previous = -1
    previous_phase = -1
    for index, row_value in enumerate(rows):
        row = _list(row_value, f"actual_open_rows[{index}]", 8)
        sequence = _uint(row[0], f"actual_open_rows[{index}].sequence")
        if sequence != previous + 1:
            raise _fail("actual_open_rows sequence must be contiguous from zero")
        previous = sequence
        phase = _uint(row[1], f"actual_open_rows[{index}].phase")
        if phase not in range(4):
            raise _fail("actual_open_rows has invalid phase")
        if phase < previous_phase:
            raise _fail("actual_open_rows phases must be nondecreasing")
        previous_phase = phase
        path = _relative_path(row[2], f"actual_open_rows[{index}].path")
        _uint(row[3], f"actual_open_rows[{index}].open_flags")
        _uint(row[4], f"actual_open_rows[{index}].st_dev")
        _uint(row[5], f"actual_open_rows[{index}].st_ino")
        length = _uint(row[6], f"actual_open_rows[{index}].byte_length")
        digest = _bstr(row[7], f"actual_open_rows[{index}].sha256", 32)
        namespace = namespace_rows.get(path)
        if namespace is None or namespace[3] != length or namespace[4] != digest:
            raise _fail("actual_open_rows must match a sealed namespace file exactly")
        # The trace may legitimately see the same input more than once; sequence,
        # not pathname, is its committed identity.
    return rows


def _actual_open_trace_root_v1(actual_open_rows: list[list[Any]]) -> bytes:
    return _root(DS_ACTUAL_OPEN_TRACE, PROTOCOL_ID, 1, actual_open_rows)


def _input_manifest(
    value: Any,
    label: str,
    argv: list[str],
    phase: int,
    primary_path: str,
    namespace_rows: dict[str, list[Any]],
    actual_open_rows: list[list[Any]],
) -> list[Any]:
    manifest = _list(value, label, 2)
    declared_argv = _argv(manifest[0], f"{label}.argv")
    if eir_canonical_cbor_encode(declared_argv) != eir_canonical_cbor_encode(argv):
        raise _fail(f"{label} argv differs from final receipt")
    rows = _list(manifest[1], f"{label}.referenced_input_rows")
    _strict_cbor_order(rows, f"{label}.referenced_input_rows")
    opened = {(row[2], row[6], row[7]) for row in actual_open_rows}
    referenced_paths: set[str] = set()
    for index, row_value in enumerate(rows):
        row = _list(row_value, f"{label}.referenced_input_rows[{index}]", 3)
        path = _relative_path(row[0], f"{label}.referenced_input_rows[{index}].path")
        length = _uint(row[1], f"{label}.referenced_input_rows[{index}].byte_length")
        digest = _bstr(row[2], f"{label}.referenced_input_rows[{index}].sha256", 32)
        namespace = namespace_rows.get(path)
        if namespace is None or namespace[3] != length or namespace[4] != digest:
            raise _fail(f"{label} referenced input is not the committed namespace file")
        if (path, length, digest) not in opened:
            raise _fail(f"{label} referenced input has no actual-open observation")
        referenced_paths.add(path)
    expected_by_path = {
        row[2]: [row[2], row[6], row[7]]
        for row in actual_open_rows
        if row[1] == phase
    }
    expected_rows = sorted(
        expected_by_path.values(), key=eir_canonical_cbor_encode
    )
    if eir_canonical_cbor_encode(rows) != eir_canonical_cbor_encode(expected_rows):
        raise _fail(f"{label} is not the exact deduplicated phase-open manifest")
    if primary_path not in referenced_paths:
        raise _fail(f"{label} must commit the primary source input")
    return manifest


def _receipt_fd_binding(value: Any) -> list[Any]:
    binding = _list(value, "receipt_fd_binding", 3)
    if _uint(binding[0], "receipt_fd_binding.fd") != 3:
        raise _fail("receipt descriptor must be 3")
    _uint(binding[1], "receipt_fd_binding.st_dev")
    _uint(binding[2], "receipt_fd_binding.st_ino")
    return binding


_PHASE_TRANSITIONS = [[0, 0, 1], [1, 1, 3], [2, 2, 4], [3, 3, 6], [4, 4, 7], [5, 5, 8], [6, 6, 9]]
_EVENT_CODES = [RECEIPT_CHANNEL_BIND, RECEIPT_PHASE_TRANSITION, RECEIPT_DRIVER_ARGV, RECEIPT_PHASE_TRANSITION,
                RECEIPT_PHASE_TRANSITION, RECEIPT_CC1_ARGV, RECEIPT_PHASE_TRANSITION, RECEIPT_PHASE_TRANSITION,
                RECEIPT_PHASE_TRANSITION, RECEIPT_PHASE_TRANSITION, RECEIPT_FINAL]


def _final_receipt(value: Any, manifest: list[Any]) -> tuple[list[Any], list[str], list[str]]:
    receipt = _list(value, "final_receipt", 8)
    _exact_uint(receipt[0], PROTOCOL_ID, "final_receipt.protocol")
    _exact_uint(receipt[1], 1, "final_receipt.version")
    binding = _receipt_fd_binding(receipt[2])
    primary_path = _relative_path(receipt[3], "final_receipt.primary_source_relative_path")
    if primary_path != manifest[2]:
        raise _fail("final receipt primary source differs from namespace")
    _arrays_only(receipt[4], "final_receipt.path_profile")
    if eir_canonical_cbor_encode(receipt[4]) != eir_canonical_cbor_encode(manifest[3]):
        raise _fail("final receipt path profile differs from namespace")
    driver = _argv(receipt[5], "final_receipt.driver_argv")
    cc1 = _argv(receipt[6], "final_receipt.cc1_argv")
    _arrays_only(receipt[7], "final_receipt.phase_transitions")
    if receipt[7] != _PHASE_TRANSITIONS:
        raise _fail("final receipt phase transitions are not exact")
    return receipt, driver, cc1


def _parse_receipt_stream(raw: Any, manifest: list[Any]) -> tuple[list[Any], list[str], list[str]]:
    stream = _bstr(raw, "receipt_stream_bytes")
    if not stream or len(stream) > COLLECTOR_RECEIPT_STREAM_MAX_BYTES_V1:
        raise _fail("receipt stream is empty or exceeds the cap")
    offset = 0
    events: list[list[Any]] = []
    while offset < len(stream):
        if len(stream) - offset < 16 or stream[offset : offset + 8] != RECEIPT_MAGIC_V1:
            raise _fail("receipt stream has malformed or truncated frame header")
        size = int.from_bytes(stream[offset + 8 : offset + 16], "big")
        offset += 16
        if size > len(stream) - offset:
            raise _fail("receipt stream frame is truncated")
        payload = stream[offset : offset + size]
        offset += size
        try:
            event = eir_canonical_cbor_decode(payload)
        except EIRPrebindingError as exc:
            raise _fail("receipt event payload is not canonical arrays-only CBOR") from exc
        if eir_canonical_cbor_encode(event) != payload:
            raise _fail("receipt event payload is noncanonical")
        events.append(_list(event, f"receipt_event[{len(events)}]", 5))
    if len(events) != 11:
        raise _fail("receipt stream must contain exactly eleven events and end at EOF")
    final: list[Any] | None = None
    driver: list[str] | None = None
    cc1: list[str] | None = None
    for sequence, event in enumerate(events):
        _exact_uint(event[0], PROTOCOL_ID, "receipt event protocol")
        _exact_uint(event[1], 1, "receipt event version")
        _exact_uint(event[2], sequence, "receipt event sequence")
        if _uint(event[3], "receipt event code") != _EVENT_CODES[sequence]:
            raise _fail("receipt event ordering is invalid")
        payload = event[4]
        if sequence == 0:
            _receipt_fd_binding(payload)
        elif sequence in (1, 3, 4, 6, 7, 8, 9):
            expected = {1: 0, 3: 1, 4: 2, 6: 3, 7: 4, 8: 5, 9: 6}[sequence]
            phase = _list(payload, "receipt phase event", 2)
            _exact_uint(phase[0], expected, "receipt phase ordinal")
            _exact_uint(phase[1], expected, "receipt phase code")
        elif sequence == 2:
            driver = _argv(payload, "receipt driver argv")
        elif sequence == 5:
            cc1 = _argv(payload, "receipt cc1 argv")
        else:
            final, final_driver, final_cc1 = _final_receipt(payload, manifest)
            if driver is None or cc1 is None:
                raise _fail("receipt final event occurred before argv events")
            if eir_canonical_cbor_encode(driver) != eir_canonical_cbor_encode(final_driver):
                raise _fail("receipt driver argv and final receipt differ")
            if eir_canonical_cbor_encode(cc1) != eir_canonical_cbor_encode(final_cc1):
                raise _fail("receipt cc1 argv and final receipt differ")
            if eir_canonical_cbor_encode(events[0][4]) != eir_canonical_cbor_encode(final[2]):
                raise _fail("receipt pipe binding and final receipt differ")
    if final is None or driver is None or cc1 is None:
        raise _fail("receipt stream has no valid final receipt")
    return final, driver, cc1


def _execution_record(
    value: Any,
    namespace_rows: dict[str, list[Any]],
    namespace_working_directory: str,
    collector_record: list[Any],
    actual_open_root: bytes,
) -> list[Any]:
    record = _list(value, "collector_execution_record", 8)
    _exact_uint(record[0], COLLECTOR_EXECUTION_RECORD_V1, "collector execution record version")
    collector_path = _relative_path(record[1], "collector_execution_record.collector_path")
    namespace = namespace_rows.get(collector_path)
    if namespace is None or COLLECTOR_EXECUTABLE not in namespace[1]:
        raise _fail("collector execution path is not the committed collector")
    if namespace[3] != collector_record[0] or namespace[4] != collector_record[1]:
        raise _fail("collector record does not match the committed collector file")
    _argv(record[2], "collector_execution_record.argv")
    if record[3] != []:
        raise _fail("collector execution environment must be the exact empty array")
    if _uint(record[4], "observed_proc_exe_byte_length", positive=True) != collector_record[0]:
        raise _fail("observed collector executable length differs from collector record")
    if _bstr(record[5], "observed_proc_exe_sha256", 32) != collector_record[1]:
        raise _fail("observed collector executable hash differs from collector record")
    working_directory = _relative_path(record[6], "observed_working_directory_relative_path")
    # The caller passes the validated manifest rather than an ambient pathname;
    # this keeps the check wholly within the capture bytes.
    if working_directory != namespace_working_directory:
        raise _fail("collector execution working directory differs from sealed namespace")
    if _bstr(record[7], "execution actual_open_trace_root", 32) != actual_open_root:
        raise _fail("collector execution actual-open root does not recompute")
    return record


def _runtime_object_row(value: Any, index: int, namespace_rows: dict[str, list[Any]]) -> list[Any]:
    row = _list(value, f"runtime_object_rows[{index}]", 5)
    path = _relative_path(row[0], f"runtime_object_rows[{index}].path")
    soname = _bstr(row[1], f"runtime_object_rows[{index}].soname")
    if len(soname) > 65_535 or (soname and b"\x00" in soname):
        raise _fail("runtime object SONAME has invalid byte representation")
    length = _uint(row[2], f"runtime_object_rows[{index}].byte_length", positive=True)
    digest = _bstr(row[3], f"runtime_object_rows[{index}].sha256", 32)
    build_id = _bstr(row[4], f"runtime_object_rows[{index}].build_id")
    if len(build_id) > 65_535:
        raise _fail("runtime object build ID exceeds the bound")
    namespace = namespace_rows.get(path)
    if namespace is None or namespace[3] != length or namespace[4] != digest:
        raise _fail("runtime object is not byte-identical to a namespace file")
    if not any(role in namespace[1] for role in (COLLECTOR_EXECUTABLE, ELF_INTERPRETER, CLANG_CPP_IMPLEMENTATION, RUNTIME_DEPENDENCY)):
        raise _fail("runtime object has no runtime namespace role")
    return row


def _runtime_binding(value: Any, namespace_record: list[Any], namespace_rows: dict[str, list[Any]], collector_record: list[Any]) -> tuple[list[Any], bytes, bytes]:
    binding = _list(value, "clang_runtime_binding", 9)
    _exact_uint(binding[0], CLANG_RUNTIME_BINDING_V2, "clang runtime binding version")
    _exact_uint(binding[1], 16, "clang runtime major")
    primary = _runtime_object_row(binding[2], 0, namespace_rows)
    interpreter = _runtime_object_row(binding[3], 0, namespace_rows)
    objects = _list(binding[4], "runtime_object_rows")
    if not objects:
        raise _fail("runtime object rows must be nonempty")
    previous: bytes | None = None
    checked: list[list[Any]] = []
    for index, row in enumerate(objects):
        checked_row = _runtime_object_row(row, index, namespace_rows)
        path_bytes = checked_row[0].encode("utf-8")
        if previous is not None and path_bytes <= previous:
            raise _fail("runtime objects must be path-sorted and unique")
        previous = path_bytes
        checked.append(checked_row)
    if sum(eir_canonical_cbor_encode(row) == eir_canonical_cbor_encode(primary) for row in checked) != 1:
        raise _fail("primary clang record must occur exactly once")
    if sum(eir_canonical_cbor_encode(row) == eir_canonical_cbor_encode(interpreter) for row in checked) != 1:
        raise _fail("ELF interpreter record must occur exactly once")
    if primary[0] == interpreter[0]:
        raise _fail("primary clang and ELF interpreter paths must differ")
    primary_ns = namespace_rows[primary[0]]
    interpreter_ns = namespace_rows[interpreter[0]]
    if CLANG_CPP_IMPLEMENTATION not in primary_ns[1] or primary[1] != b"libclang-cpp.so.16":
        raise _fail("primary clang record lacks exact role or SONAME")
    if ELF_INTERPRETER not in interpreter_ns[1]:
        raise _fail("interpreter record lacks ELF interpreter role")
    role_seven = [row for row in checked if CLANG_CPP_IMPLEMENTATION in namespace_rows[row[0]][1]]
    if len(role_seven) != 1 or eir_canonical_cbor_encode(role_seven[0]) != eir_canonical_cbor_encode(primary):
        raise _fail("no second runtime object may claim the primary clang role")
    collector_indices = [i for i, row in enumerate(checked) if COLLECTOR_EXECUTABLE in namespace_rows[row[0]][1] and row[2] == collector_record[0] and row[3] == collector_record[1]]
    if len(collector_indices) != 1:
        raise _fail("collector runtime object membership is invalid")

    observations = _list(binding[5], "runtime_observation_rows")
    if len(observations) != len(checked):
        raise _fail("runtime observation coverage must be one-to-one")
    seen_indices: set[int] = set()
    for sequence, row_value in enumerate(observations):
        row = _list(row_value, f"runtime_observation_rows[{sequence}]", 8)
        if _uint(row[0], "runtime observation sequence") != sequence:
            raise _fail("runtime observation sequence must be contiguous")
        kind = _uint(row[1], "runtime observation kind")
        object_index = _uint(row[2], "runtime observation object index")
        if object_index >= len(checked) or object_index in seen_indices:
            raise _fail("runtime observation object coverage is invalid")
        seen_indices.add(object_index)
        _uint(row[3], "runtime observation st_dev")
        _uint(row[4], "runtime observation st_ino")
        offset = _uint(row[5], "runtime observation file_offset")
        mapping_length = _uint(row[6], "runtime observation mapping_length")
        protection = _uint(row[7], "runtime observation protection_flags")
        is_collector = object_index == collector_indices[0]
        if is_collector:
            if kind != RUNTIME_OBSERVATION_EXEC_PROC_EXE or (offset, mapping_length, protection) != (0, 0, 0):
                raise _fail("collector runtime observation must be exact exec-proc-exe")
        elif kind not in (RUNTIME_OBSERVATION_MMAP_FD_PROT_EXEC, RUNTIME_OBSERVATION_PROC_MAP_FILES_PROT_EXEC) or mapping_length == 0 or protection & PROT_EXEC == 0:
            raise _fail("non-collector runtime observation must prove executable mapping")
    if seen_indices != set(range(len(checked))):
        raise _fail("runtime observations omit an object")
    bound_runtime_root = _bstr(binding[6], "bound_runtime_root", 32)
    if bound_runtime_root != namespace_record[2]:
        raise _fail("bound runtime root differs from sealed namespace")
    observation_root = _root(DS_RUNTIME_OBSERVATION, PROTOCOL_ID, CLANG_RUNTIME_BINDING_V2, checked, observations)
    if _bstr(binding[7], "runtime_observation_root", 32) != observation_root:
        raise _fail("runtime observation root does not recompute")
    closure_root = _root(DS_RUNTIME_CLOSURE, PROTOCOL_ID, CLANG_RUNTIME_BINDING_V2, 16, primary, interpreter, checked, observations, bound_runtime_root, observation_root)
    if _bstr(binding[8], "clang_runtime_closure_root", 32) != closure_root:
        raise _fail("clang runtime closure root does not recompute")
    return binding, observation_root, closure_root


def _invocation(value: Any, manifest: list[Any], namespace_rows: dict[str, list[Any]]) -> tuple[list[Any], bytes]:
    record = _list(value, "actual_invocation_record", 8)
    _exact_uint(record[0], ACTUAL_COLLECTOR_INVOCATION_V2, "actual invocation record version")
    stream = _bstr(record[1], "receipt_stream_bytes")
    if _uint(record[2], "receipt_stream_byte_length") != len(stream):
        raise _fail("receipt stream length does not match bytes")
    stream_hash = sha256(stream).digest()
    if _bstr(record[3], "receipt_stream_sha256", 32) != stream_hash:
        raise _fail("receipt stream hash does not match bytes")
    final, driver, cc1 = _parse_receipt_stream(stream, manifest)
    actual_open_rows = _actual_open_rows(record[6], namespace_rows)
    if not any(row[2] == manifest[2] for row in actual_open_rows):
        raise _fail("the committed primary source has no actual-open observation")
    driver_manifest = _input_manifest(
        record[4], "driver_input_manifest", driver, 1, manifest[2], namespace_rows, actual_open_rows
    )
    cc1_manifest = _input_manifest(
        record[5], "cc1_input_manifest", cc1, 2, manifest[2], namespace_rows, actual_open_rows
    )
    open_root = _actual_open_trace_root_v1(actual_open_rows)
    invocation_root = _root(DS_INVOCATION, PROTOCOL_ID, ACTUAL_COLLECTOR_INVOCATION_V2, len(stream), stream_hash, final, driver_manifest, cc1_manifest, open_root)
    if _bstr(record[7], "invocation_root", 32) != invocation_root:
        raise _fail("invocation root does not recompute")
    return record, invocation_root


def _harness(value: Any) -> tuple[list[Any], bytes]:
    record = _list(value, "capture_harness_record", 4)
    entry = _component_record(record[0], "capture_entry_record")
    interpreter = _component_record(record[1], "capture_interpreter_record")
    supervisor = _component_record(record[2], "native_supervisor_record")
    root = _root(DS_HARNESS_CLOSURE, PROTOCOL_ID, 1, entry, interpreter, supervisor)
    if _bstr(record[3], "capture_harness_closure_root", 32) != root:
        raise _fail("capture harness closure root does not recompute")
    return record, root


def _termination(value: Any) -> list[Any]:
    record = _list(value, "termination_record", 3)
    if _uint(record[0], "collector_exit_status") != 0 or _uint(record[1], "stderr_byte_length") != 0:
        raise _fail("capture termination was not successful")
    if _bstr(record[2], "stderr_sha256", 32) != sha256(b"").digest():
        raise _fail("successful capture stderr hash must be SHA256(empty)")
    return record


def _validate_raw_collector_capture_v2(value: Any) -> CaptureV2Roots:
    """Validate a complete in-memory Capture V2 value and recompute all roots.

    The result intentionally has every authority bit false.  It validates only
    claims encoded in the supplied bytes; live-custody claims remain in
    ``external_evidence_prerequisites``.
    """

    capture = _list(value, "raw_collector_capture", 10)
    _exact_uint(capture[0], PROTOCOL_ID, "capture protocol")
    _exact_uint(capture[1], RAW_COLLECTOR_CAPTURE_V2, "capture version")
    collector = _component_record(capture[2], "collector_record")
    namespace_record, namespace_rows = _namespace(capture[3])
    invocation, invocation_root = _invocation(capture[5], namespace_record[0], namespace_rows)
    actual_open_root = _actual_open_trace_root_v1(invocation[6])
    _execution_record(capture[4], namespace_rows, namespace_record[0][1], collector, actual_open_root)
    _, observation_root, closure_root = _runtime_binding(capture[6], namespace_record, namespace_rows, collector)
    raw = _list(capture[7], "raw_collector_record", 2)
    raw_length = _uint(raw[0], "raw_collector_byte_length", positive=True)
    if raw_length > RAW_COLLECTOR_CAPTURE_MAX_BYTES_V1:
        raise _fail("raw collector byte length exceeds 64 MiB capture cap")
    _bstr(raw[1], "raw_collector_sha256", 32)
    _, harness_root = _harness(capture[8])
    _termination(capture[9])
    namespace_roots = derive_capture_namespace_roots_v1(namespace_record[0])
    return CaptureV2Roots(
        source_root=namespace_roots.source_root,
        runtime_root=namespace_roots.runtime_root,
        execution_namespace_root=namespace_roots.execution_namespace_root,
        actual_open_trace_root=actual_open_root,
        invocation_root=invocation_root,
        runtime_observation_root=observation_root,
        clang_runtime_closure_root=closure_root,
        capture_harness_closure_root=harness_root,
        raw_collector_capture_root=_root(DS_CAPTURE_ROOT, capture),
    )


def validate_raw_collector_capture_v2(value: Any) -> CaptureV2Roots:
    """Fail closed with the Amendment-10 public failure code for any bad capture."""

    try:
        return _validate_raw_collector_capture_v2(value)
    except EIRPrebindingError as exc:
        if exc.code == M0_DIAGNOSTIC_INVENTORY_INCOMPLETE:
            raise
        raise _fail(str(exc)) from exc


def raw_collector_capture_root_v2(value: Any) -> bytes:
    """Validate one complete Capture V2 value and return its top-level root."""

    return validate_raw_collector_capture_v2(value).raw_collector_capture_root


def encode_raw_collector_capture_v2(value: Any) -> bytes:
    """Validate and canonically encode one complete Capture V2 value."""

    validate_raw_collector_capture_v2(value)
    encoded = eir_canonical_cbor_encode(value)
    if eir_canonical_cbor_decode(encoded) != value:
        raise _fail("Capture V2 encoder round trip failed")
    return encoded


def decode_raw_collector_capture_v2(raw: bytes) -> CaptureV2Roots:
    """Decode canonical arrays-only Capture V2 bytes without any host access."""

    if type(raw) is not bytes:
        raise _fail("Capture V2 bytes must be a byte string")
    try:
        value = eir_canonical_cbor_decode(raw)
    except EIRPrebindingError as exc:
        raise _fail("Capture V2 bytes are not canonical arrays-only CBOR") from exc
    if eir_canonical_cbor_encode(value) != raw:
        raise _fail("Capture V2 bytes are noncanonical")
    return validate_raw_collector_capture_v2(value)


__all__ = [
    "ACTUAL_COLLECTOR_INVOCATION_V2",
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "CaptureV2Roots",
    "CLANG_RUNTIME_BINDING_V2",
    "COLLECTOR_RECEIPT_STREAM_MAX_BYTES_V1",
    "ENGINE_WIRING_AUTHORITY",
    "EXTERNAL_EVIDENCE_PREREQUISITES",
    "HOLDOUT_ACCESS_AUTHORITY",
    "M0_DIAGNOSTIC_INVENTORY_INCOMPLETE",
    "PERMIT_AUTHORITY",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "RAW_COLLECTOR_CAPTURE_MAX_BYTES_V1",
    "RAW_COLLECTOR_CAPTURE_V2",
    "SEALED_HOLDOUT_ACCESS_AUTHORITY",
    "UPLOAD_AUTHORITY",
    "decode_raw_collector_capture_v2",
    "encode_raw_collector_capture_v2",
    "raw_collector_capture_root_v2",
    "validate_raw_collector_capture_v2",
]
