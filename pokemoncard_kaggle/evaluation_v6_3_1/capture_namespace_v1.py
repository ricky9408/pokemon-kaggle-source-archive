"""Pure, zero-authority CAPTURE_NAMESPACE_MANIFEST_V1 validation and roots.

This module implements only Amendment 8 Sections 1--2's manifest wire and
domain-separated commitments.  It accepts already-materialized values or
canonical CBOR bytes; it never reads host state, executes a process, creates a
namespace, issues a permit, or authorizes an upload.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .eir_prebinding import EIRPrebindingError, eir_canonical_cbor_decode, eir_canonical_cbor_encode


PROTOCOL_ID = 631302
CAPTURE_NAMESPACE_MANIFEST_V1 = 1

COLLECTOR_EXECUTABLE = 1
PRIMARY_SOURCE = 2
SOURCE_INPUT = 3
DRIVER_AUXILIARY = 4
CC1_AUXILIARY = 5
ELF_INTERPRETER = 6
CLANG_CPP_IMPLEMENTATION = 7
RUNTIME_DEPENDENCY = 8

SOURCE_ROLE_CODES = frozenset((PRIMARY_SOURCE, SOURCE_INPUT, DRIVER_AUXILIARY, CC1_AUXILIARY))
RUNTIME_ROLE_CODES = frozenset(
    (COLLECTOR_EXECUTABLE, ELF_INTERPRETER, CLANG_CPP_IMPLEMENTATION, RUNTIME_DEPENDENCY)
)
VALID_ROLE_CODES = SOURCE_ROLE_CODES | RUNTIME_ROLE_CODES

CAPTURE_NAMESPACE_INVALID_TYPE = "CAPTURE_NAMESPACE_INVALID_TYPE"
CAPTURE_NAMESPACE_SCHEMA_INVALID = "CAPTURE_NAMESPACE_SCHEMA_INVALID"
CAPTURE_NAMESPACE_PATH_INVALID = "CAPTURE_NAMESPACE_PATH_INVALID"
CAPTURE_NAMESPACE_ROLE_INVALID = "CAPTURE_NAMESPACE_ROLE_INVALID"
CAPTURE_NAMESPACE_ORDER_INVALID = "CAPTURE_NAMESPACE_ORDER_INVALID"
CAPTURE_NAMESPACE_MODE_INVALID = "CAPTURE_NAMESPACE_MODE_INVALID"
CAPTURE_NAMESPACE_LENGTH_INVALID = "CAPTURE_NAMESPACE_LENGTH_INVALID"
CAPTURE_NAMESPACE_DIGEST_INVALID = "CAPTURE_NAMESPACE_DIGEST_INVALID"
CAPTURE_NAMESPACE_ROOT_MISMATCH = "CAPTURE_NAMESPACE_ROOT_MISMATCH"
CAPTURE_NAMESPACE_CANONICAL_ENCODING = "CAPTURE_NAMESPACE_CANONICAL_ENCODING"

DS_SOURCE_ROOT = b"V631302_CAPTURE_SOURCE_ROOT_V1"
DS_RUNTIME_ROOT = b"V631302_CAPTURE_RUNTIME_ROOT_V1"
DS_EXECUTION_NAMESPACE_ROOT = b"V631302_CAPTURE_EXECUTION_NAMESPACE_V1"

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


@dataclass(frozen=True)
class CaptureNamespaceRootsV1:
    """Pure manifest commitments; these roots carry no operational authority."""

    source_root: bytes
    runtime_root: bytes
    execution_namespace_root: bytes
    state: str = "CAPTURE_NAMESPACE_MANIFEST_V1_BYTES_ONLY"
    authority: bool = AUTHORITY
    engine_wiring_authority: bool = ENGINE_WIRING_AUTHORITY
    upload_authority: bool = UPLOAD_AUTHORITY
    permit_authority: bool = PERMIT_AUTHORITY
    holdout_access_authority: bool = HOLDOUT_ACCESS_AUTHORITY
    agent_modification_authority: bool = AGENT_MODIFICATION_AUTHORITY
    calibration_upload_authority: bool = CALIBRATION_UPLOAD_AUTHORITY
    production_upload_authority: bool = PRODUCTION_UPLOAD_AUTHORITY
    sealed_holdout_access_authority: bool = SEALED_HOLDOUT_ACCESS_AUTHORITY


def _fail(code: str, message: str) -> EIRPrebindingError:
    return EIRPrebindingError(code, message)


def _require_list(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        raise _fail(CAPTURE_NAMESPACE_INVALID_TYPE, f"{label} must be a CBOR array")
    return value


def _require_uint(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise _fail(CAPTURE_NAMESPACE_INVALID_TYPE, f"{label} must be a uint64")
    return value


def _require_bstr32(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise _fail(CAPTURE_NAMESPACE_DIGEST_INVALID, f"{label} must be a 32-byte string")
    return value


def _require_text(value: Any, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise _fail(CAPTURE_NAMESPACE_PATH_INVALID, f"{label} must be nonempty NUL-free text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(CAPTURE_NAMESPACE_PATH_INVALID, f"{label} must be valid UTF-8") from exc
    return value


def _relative_path(value: Any, label: str) -> str:
    path = _require_text(value, label)
    if path.startswith("/") or "\\" in path:
        raise _fail(CAPTURE_NAMESPACE_PATH_INVALID, f"{label} must be a slash-separated relative path")
    components = path.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise _fail(CAPTURE_NAMESPACE_PATH_INVALID, f"{label} has a noncanonical path component")
    return path


def _validate_arrays_only(value: Any, label: str) -> None:
    """Restrict direct-value inputs to the arrays-only scalar CBOR profile."""

    if type(value) is list:
        for index, item in enumerate(value):
            _validate_arrays_only(item, f"{label}[{index}]")
        return
    if type(value) is bool or value is None or type(value) is float:
        raise _fail(CAPTURE_NAMESPACE_INVALID_TYPE, f"{label} is not an allowed canonical-CBOR scalar")
    if type(value) is int:
        _require_uint(value, label)
        return
    if type(value) is bytes:
        return
    if type(value) is str:
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise _fail(CAPTURE_NAMESPACE_INVALID_TYPE, f"{label} is not valid UTF-8") from exc
        return
    raise _fail(CAPTURE_NAMESPACE_INVALID_TYPE, f"{label} is not an allowed canonical-CBOR value")


def _validate_role_codes(value: Any, label: str) -> list[int]:
    roles = _require_list(value, label)
    if not roles:
        raise _fail(CAPTURE_NAMESPACE_ROLE_INVALID, f"{label} must be nonempty")
    previous = 0
    for index, role in enumerate(roles):
        role = _require_uint(role, f"{label}[{index}]")
        if role not in VALID_ROLE_CODES:
            raise _fail(CAPTURE_NAMESPACE_ROLE_INVALID, f"{label}[{index}] is not a valid role code")
        if role <= previous:
            raise _fail(CAPTURE_NAMESPACE_ORDER_INVALID, f"{label} must be strictly increasing")
        previous = role
    return roles


def _validate_file_row(value: Any, index: int) -> list[Any]:
    row = _require_list(value, f"file_rows[{index}]")
    if len(row) != 5:
        raise _fail(CAPTURE_NAMESPACE_SCHEMA_INVALID, f"file_rows[{index}] must have five fields")
    _relative_path(row[0], f"file_rows[{index}].relative_path")
    roles = _validate_role_codes(row[1], f"file_rows[{index}].role_codes")
    mode = _require_uint(row[2], f"file_rows[{index}].normalized_mode")
    expected_mode = 0o555 if COLLECTOR_EXECUTABLE in roles else 0o444
    if mode != expected_mode:
        raise _fail(CAPTURE_NAMESPACE_MODE_INVALID, f"file_rows[{index}] has the wrong normalized mode")
    _require_uint(row[3], f"file_rows[{index}].byte_length")
    _require_bstr32(row[4], f"file_rows[{index}].sha256")
    return row


def validate_capture_namespace_manifest_v1(value: Any) -> list[Any]:
    """Fail-closed validation of the Amendment-8 Section-2 manifest value."""

    manifest = _require_list(value, "manifest")
    if len(manifest) != 5:
        raise _fail(CAPTURE_NAMESPACE_SCHEMA_INVALID, "manifest must have five fields")
    if _require_uint(manifest[0], "manifest.version") != CAPTURE_NAMESPACE_MANIFEST_V1:
        raise _fail(CAPTURE_NAMESPACE_SCHEMA_INVALID, "manifest has an unsupported schema version")
    _relative_path(manifest[1], "working_directory_relative_path")
    primary_path = _relative_path(manifest[2], "primary_source_relative_path")
    path_profile = _require_list(manifest[3], "path_profile")
    _validate_arrays_only(path_profile, "path_profile")
    rows = _require_list(manifest[4], "file_rows")
    if not rows:
        raise _fail(CAPTURE_NAMESPACE_SCHEMA_INVALID, "file_rows must be nonempty")

    previous_path_bytes: bytes | None = None
    paths: set[str] = set()
    collector_count = 0
    primary_count = 0
    for index, row in enumerate(rows):
        checked = _validate_file_row(row, index)
        path = checked[0]
        path_bytes = path.encode("utf-8")
        if path in paths:
            raise _fail(CAPTURE_NAMESPACE_ORDER_INVALID, "file_rows paths must be unique")
        if previous_path_bytes is not None and path_bytes <= previous_path_bytes:
            raise _fail(CAPTURE_NAMESPACE_ORDER_INVALID, "file_rows must be sorted by UTF-8 path bytes")
        paths.add(path)
        previous_path_bytes = path_bytes
        collector_count += int(COLLECTOR_EXECUTABLE in checked[1])
        primary_count += int(PRIMARY_SOURCE in checked[1])
        if PRIMARY_SOURCE in checked[1] and path != primary_path:
            raise _fail(CAPTURE_NAMESPACE_SCHEMA_INVALID, "PRIMARY_SOURCE row must match primary_source_relative_path")

    if collector_count != 1:
        raise _fail(CAPTURE_NAMESPACE_ROLE_INVALID, "manifest must contain exactly one collector executable")
    if primary_count != 1:
        raise _fail(CAPTURE_NAMESPACE_ROLE_INVALID, "manifest must contain exactly one primary source")
    if primary_path not in paths:
        raise _fail(CAPTURE_NAMESPACE_SCHEMA_INVALID, "primary_source_relative_path is absent from file_rows")
    return manifest


def decode_capture_namespace_manifest_v1(raw: bytes) -> list[Any]:
    """Decode and validate exact arrays-only canonical CBOR manifest bytes."""

    if type(raw) is not bytes:
        raise _fail(CAPTURE_NAMESPACE_INVALID_TYPE, "manifest bytes must be a byte string")
    try:
        manifest = eir_canonical_cbor_decode(raw)
    except EIRPrebindingError as exc:
        raise _fail(CAPTURE_NAMESPACE_CANONICAL_ENCODING, str(exc)) from exc
    validate_capture_namespace_manifest_v1(manifest)
    if eir_canonical_cbor_encode(manifest) != raw:
        raise _fail(CAPTURE_NAMESPACE_CANONICAL_ENCODING, "manifest CBOR bytes are not canonical")
    return manifest


def encode_capture_namespace_manifest_v1(manifest: Any) -> bytes:
    """Validate and canonically encode a manifest without touching host state."""

    checked = validate_capture_namespace_manifest_v1(manifest)
    encoded = eir_canonical_cbor_encode(checked)
    if eir_canonical_cbor_decode(encoded) != checked:
        raise _fail(CAPTURE_NAMESPACE_CANONICAL_ENCODING, "manifest encoder round trip failed")
    return encoded


def _filtered_rows(manifest: Any, roles: frozenset[int]) -> list[list[Any]]:
    checked = validate_capture_namespace_manifest_v1(manifest)
    return [row for row in checked[4] if any(role in roles for role in row[1])]


def capture_source_root_v1(manifest: Any) -> bytes:
    """Derive Amendment-8's source commitment from the canonical source rows."""

    return sha256(
        eir_canonical_cbor_encode([DS_SOURCE_ROOT, PROTOCOL_ID, CAPTURE_NAMESPACE_MANIFEST_V1, _filtered_rows(manifest, SOURCE_ROLE_CODES)])
    ).digest()


def capture_runtime_root_v1(manifest: Any) -> bytes:
    """Derive Amendment-8's runtime commitment from the canonical runtime rows."""

    return sha256(
        eir_canonical_cbor_encode([DS_RUNTIME_ROOT, PROTOCOL_ID, CAPTURE_NAMESPACE_MANIFEST_V1, _filtered_rows(manifest, RUNTIME_ROLE_CODES)])
    ).digest()


def derive_capture_namespace_roots_v1(manifest: Any) -> CaptureNamespaceRootsV1:
    """Return all three pure Section-2 roots with permanently false authority bits."""

    checked = validate_capture_namespace_manifest_v1(manifest)
    source_root = capture_source_root_v1(checked)
    runtime_root = capture_runtime_root_v1(checked)
    execution_namespace_root = sha256(
        eir_canonical_cbor_encode(
            [
                DS_EXECUTION_NAMESPACE_ROOT,
                PROTOCOL_ID,
                CAPTURE_NAMESPACE_MANIFEST_V1,
                checked,
                source_root,
                runtime_root,
            ]
        )
    ).digest()
    return CaptureNamespaceRootsV1(source_root, runtime_root, execution_namespace_root)


def capture_execution_namespace_root_v1(manifest: Any) -> bytes:
    return derive_capture_namespace_roots_v1(manifest).execution_namespace_root


def validate_capture_namespace_roots_v1(
    manifest: Any,
    source_root: Any,
    runtime_root: Any,
    execution_namespace_root: Any,
) -> CaptureNamespaceRootsV1:
    """Fail closed unless all caller-supplied Section-2 root claims recompute exactly."""

    expected = derive_capture_namespace_roots_v1(manifest)
    claims = (
        ("source_root", _require_bstr32(source_root, "source_root"), expected.source_root),
        ("runtime_root", _require_bstr32(runtime_root, "runtime_root"), expected.runtime_root),
        (
            "execution_namespace_root",
            _require_bstr32(execution_namespace_root, "execution_namespace_root"),
            expected.execution_namespace_root,
        ),
    )
    for label, claimed, derived in claims:
        if claimed != derived:
            raise _fail(CAPTURE_NAMESPACE_ROOT_MISMATCH, f"{label} does not match the manifest")
    return expected


__all__ = [
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "CAPTURE_NAMESPACE_CANONICAL_ENCODING",
    "CAPTURE_NAMESPACE_DIGEST_INVALID",
    "CAPTURE_NAMESPACE_INVALID_TYPE",
    "CAPTURE_NAMESPACE_LENGTH_INVALID",
    "CAPTURE_NAMESPACE_MANIFEST_V1",
    "CAPTURE_NAMESPACE_MODE_INVALID",
    "CAPTURE_NAMESPACE_ORDER_INVALID",
    "CAPTURE_NAMESPACE_PATH_INVALID",
    "CAPTURE_NAMESPACE_ROLE_INVALID",
    "CAPTURE_NAMESPACE_ROOT_MISMATCH",
    "CAPTURE_NAMESPACE_SCHEMA_INVALID",
    "CaptureNamespaceRootsV1",
    "CLANG_CPP_IMPLEMENTATION",
    "COLLECTOR_EXECUTABLE",
    "DRIVER_AUXILIARY",
    "ELF_INTERPRETER",
    "ENGINE_WIRING_AUTHORITY",
    "HOLDOUT_ACCESS_AUTHORITY",
    "PERMIT_AUTHORITY",
    "PRIMARY_SOURCE",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "RUNTIME_DEPENDENCY",
    "SEALED_HOLDOUT_ACCESS_AUTHORITY",
    "SOURCE_INPUT",
    "UPLOAD_AUTHORITY",
    "VALID_ROLE_CODES",
    "capture_execution_namespace_root_v1",
    "capture_runtime_root_v1",
    "capture_source_root_v1",
    "decode_capture_namespace_manifest_v1",
    "derive_capture_namespace_roots_v1",
    "encode_capture_namespace_manifest_v1",
    "validate_capture_namespace_manifest_v1",
    "validate_capture_namespace_roots_v1",
]
