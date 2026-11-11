"""Deterministic, zero-authority Stage-1 trailer profile encodings.

This module implements only Section 4 of
``V631302_STAGE1_AUTHENTICATED_TRAILER_LAUNCH_GATE_FREEZE_1``.  It consumes
already-produced byte evidence; it never reads a filesystem, executes a
binary, issues a permit, accesses a holdout, or authorizes an upload.

The literal SupervisorBuildProfileV1 array in the binding has fourteen items
(two schema fields, six manifest hashes, five artifact hashes, and the image
profile hash).  ``SUPERVISOR_BUILD_PROFILE_FIELD_COUNT`` intentionally records
that frozen wire fact rather than adding two unaudited fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import struct
from typing import Final, Iterable, Sequence

from .canonical_trace_codec import canonical_cbor_decode, canonical_cbor_encode
from .launch_gate_decoder_manifest_v1 import (
    LaunchGateDecoderAgreementResult,
    compare_launch_gate_decoder_outputs_v1,
)
from .launch_gate_stage1_validation import (
    LaunchGateTrailerEvidenceV1,
    LaunchGateTrailerValidationResultV1,
)


PROTOCOL_ID: Final = 631302
PROFILE_VERSION: Final = 1
EM_X86_64: Final = 62
PAGE_SIZE: Final = 4096
EMPTY_PATH_OFFSET: Final = 4095
PINNED_GATE_CODE_SIZE: Final = 874
PINNED_GATE_OBJECT_SIZE: Final = 8688
PINNED_GATE_OBJECT_SHA256: Final = bytes.fromhex(
    "c20ea3a183f40c61ca3396771fb92cb948cc603b81e966486996f48bab84a530"
)
PINNED_GATE_PAGE_SHA256: Final = bytes.fromhex(
    "91fce3ca09e908b9e51d73e887f67a14ba7b5c250180cb613f871666f12277f5"
)
SHA256_SIZE: Final = 32
ELF_HEADER_SIZE: Final = 64
PROGRAM_HEADER_SIZE: Final = 56
ET_DYN: Final = 3
LAUNCH_GATE_IMAGE_PROFILE_FIELD_COUNT: Final = 19
SUPERVISOR_BUILD_PROFILE_FIELD_COUNT: Final = 14

_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_MAX_U64: Final = (1 << 64) - 1

# This profile layer is descriptive, offline, and deliberately incapable of
# changing campaign state.
ZERO_AUTHORITY: Final = True
AUTHORITY: Final = False
CALIBRATION_UPLOAD_AUTHORIZED: Final = False
PRODUCTION_UPLOAD_AUTHORIZED: Final = False
HOLDOUT_ACCESS_AUTHORIZED: Final = False
AGENT_MODIFICATION_AUTHORIZED: Final = False
PERMIT_AUTHORITY: Final = False
NO_UPLOAD: Final = "NO_UPLOAD"


class LaunchGateStage1ProfileError(ValueError):
    """Fail-closed error for malformed deterministic profile evidence."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str) -> None:
    raise LaunchGateStage1ProfileError(code, message)


def _require_bytes(value: object, label: str) -> bytes:
    if type(value) is not bytes:
        _fail("PROFILE_BYTES_REQUIRED", f"{label} must be immutable bytes")
    return value


def _require_u64(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value > (1 << 64) - 1:
        _fail("PROFILE_U64_REQUIRED", f"{label} must be a nonnegative uint64")
    return value


def _require_hash(value: object, label: str) -> bytes:
    value = _require_bytes(value, label)
    if len(value) != SHA256_SIZE:
        _fail("PROFILE_HASH_LENGTH_INVALID", f"{label} must be exactly 32 bytes")
    return value


def _sha256(value: bytes) -> bytes:
    return sha256(value).digest()


def _align_up(value: int, alignment: int) -> int:
    if value < 0 or alignment <= 0 or alignment & (alignment - 1):
        _fail("PROFILE_ALIGNMENT_INVALID", "alignment request is invalid")
    return value if value % alignment == 0 else value + alignment - value % alignment


def _derive_program_header_table(base_elf: bytes) -> bytes:
    """Derive the frozen program-header slice from the exact base ELF bytes."""

    if len(base_elf) < _ELF_HEADER.size:
        _fail("PROFILE_ELF_HEADER_TRUNCATED", "base_elf has no complete ELF64 header")
    try:
        fields = _ELF_HEADER.unpack_from(base_elf)
    except struct.error as exc:
        _fail("PROFILE_ELF_HEADER_INVALID", f"base_elf header is malformed: {exc}")
    ident = fields[0]
    if ident[:7] != b"\x7fELF\x02\x01\x01":
        _fail("PROFILE_ELF_IDENTITY_INVALID", "base_elf is not current ELF64 little-endian")
    if fields[1] != ET_DYN or fields[2] != EM_X86_64 or fields[3] != 1:
        _fail("PROFILE_ELF_IDENTITY_INVALID", "base_elf is not current x86_64 ET_DYN")
    e_phoff = fields[5]
    e_ehsize = fields[8]
    e_phentsize = fields[9]
    e_phnum = fields[10]
    if (
        e_ehsize != ELF_HEADER_SIZE
        or e_phnum == 0
        or e_phentsize != PROGRAM_HEADER_SIZE
        or e_phoff < ELF_HEADER_SIZE
        or e_phoff % 8
    ):
        _fail("PROFILE_PROGRAM_HEADER_INVALID", "base_elf program-header metadata is invalid")
    table_size = e_phnum * e_phentsize
    if e_phoff > _MAX_U64 - table_size:
        _fail("PROFILE_PROGRAM_HEADER_OVERFLOW", "base_elf program-header range overflows uint64")
    end = e_phoff + table_size
    if end > len(base_elf):
        _fail("PROFILE_PROGRAM_HEADER_TRUNCATED", "base_elf program-header table is truncated")
    return base_elf[e_phoff:end]


def _restricted_value(value: object, *, label: str) -> None:
    """Accept exactly the CBOR value kinds permitted by Section 4."""

    if type(value) is int:
        if value < 0:
            _fail("PROFILE_CBOR_NEGATIVE_INTEGER", f"{label} contains a negative integer")
        return
    if type(value) is bytes:
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _restricted_value(item, label=f"{label}[{index}]")
        return
    _fail(
        "PROFILE_CBOR_TYPE_FORBIDDEN",
        f"{label} contains forbidden {type(value).__name__}; only arrays, byte strings, and nonnegative integers are allowed",
    )


def validate_restricted_canonical_cbor(raw: object, *, label: str) -> bytes:
    """Require one canonical CBOR array using only the Section-4 value kinds."""

    raw = _require_bytes(raw, label)
    try:
        decoded = canonical_cbor_decode(raw)
    except Exception as exc:  # Codec exceptions are intentionally normalized here.
        _fail("PROFILE_CBOR_INVALID", f"{label} is not canonical CBOR: {exc}")
    if type(decoded) is not list:
        _fail("PROFILE_CBOR_ROOT_INVALID", f"{label} must be an array")
    _restricted_value(decoded, label=label)
    if canonical_cbor_encode(decoded) != raw:
        _fail("PROFILE_CBOR_NONCANONICAL", f"{label} does not round-trip canonically")
    return raw


def _require_exact_list(raw: object, *, label: str, count: int) -> list[object]:
    raw = validate_restricted_canonical_cbor(raw, label=label)
    decoded = canonical_cbor_decode(raw)
    assert type(decoded) is list  # Established by validate_restricted_canonical_cbor.
    if len(decoded) != count:
        _fail("PROFILE_FIELD_COUNT_INVALID", f"{label} must contain exactly {count} fields")
    return decoded


def _assert_schema_prefix(values: Sequence[object], *, label: str) -> None:
    if _require_u64(values[0], f"{label}[0]") != PROTOCOL_ID:
        _fail("PROFILE_PROTOCOL_INVALID", f"{label} protocol id is not {PROTOCOL_ID}")
    if _require_u64(values[1], f"{label}[1]") != PROFILE_VERSION:
        _fail("PROFILE_VERSION_INVALID", f"{label} version is not {PROFILE_VERSION}")


@dataclass(frozen=True, slots=True)
class LaunchGateImageProfileV1:
    """The exact nineteen-field LaunchGateImageProfileV1 wire record."""

    base_length: int
    base_elf_sha256: bytes
    base_e_entry: int
    base_program_header_table_sha256: bytes
    gate_file_offset: int
    gate_code_size: int
    gate_code_sha256: bytes
    gate_page_sha256: bytes
    normalized_instruction_manifest_sha256: bytes
    normalized_cfg_manifest_sha256: bytes
    final_length: int
    final_image_sha256: bytes

    def __post_init__(self) -> None:
        _require_u64(self.base_length, "base_length")
        _require_hash(self.base_elf_sha256, "base_elf_sha256")
        _require_u64(self.base_e_entry, "base_e_entry")
        _require_hash(self.base_program_header_table_sha256, "base_program_header_table_sha256")
        if _require_u64(self.gate_file_offset, "gate_file_offset") != _align_up(self.base_length, PAGE_SIZE):
            _fail("PROFILE_GATE_OFFSET_INVALID", "gate_file_offset must equal aligned base_length")
        if _require_u64(self.gate_code_size, "gate_code_size") != PINNED_GATE_CODE_SIZE:
            _fail("PROFILE_GATE_CODE_SIZE_INVALID", "gate_code_size is not the corrected pinned value 874")
        for label, value in (
            ("gate_code_sha256", self.gate_code_sha256),
            ("gate_page_sha256", self.gate_page_sha256),
            ("normalized_instruction_manifest_sha256", self.normalized_instruction_manifest_sha256),
            ("normalized_cfg_manifest_sha256", self.normalized_cfg_manifest_sha256),
            ("final_image_sha256", self.final_image_sha256),
        ):
            _require_hash(value, label)
        if self.gate_page_sha256 != PINNED_GATE_PAGE_SHA256:
            _fail("PROFILE_GATE_PAGE_HASH_INVALID", "gate page is not the corrected pinned revision")
        if _require_u64(self.final_length, "final_length") != self.gate_file_offset + PAGE_SIZE:
            _fail("PROFILE_FINAL_LENGTH_INVALID", "final_length must equal gate_file_offset + 4096")

    def as_array(self) -> list[object]:
        return [
            PROTOCOL_ID,
            PROFILE_VERSION,
            EM_X86_64,
            PAGE_SIZE,
            self.base_length,
            self.base_elf_sha256,
            self.base_e_entry,
            self.base_program_header_table_sha256,
            self.gate_file_offset,
            PAGE_SIZE,
            0,
            self.gate_code_size,
            EMPTY_PATH_OFFSET,
            self.gate_code_sha256,
            self.gate_page_sha256,
            self.normalized_instruction_manifest_sha256,
            self.normalized_cfg_manifest_sha256,
            self.final_length,
            self.final_image_sha256,
        ]

    def canonical_cbor(self) -> bytes:
        return canonical_cbor_encode(self.as_array())

    def sha256(self) -> bytes:
        return _sha256(self.canonical_cbor())

    @classmethod
    def from_canonical_cbor(cls, raw: object) -> "LaunchGateImageProfileV1":
        values = _require_exact_list(
            raw,
            label="LaunchGateImageProfileV1",
            count=LAUNCH_GATE_IMAGE_PROFILE_FIELD_COUNT,
        )
        _assert_schema_prefix(values, label="LaunchGateImageProfileV1")
        if _require_u64(values[2], "LaunchGateImageProfileV1[2]") != EM_X86_64:
            _fail("PROFILE_MACHINE_INVALID", "image profile machine is not EM_X86_64")
        if _require_u64(values[3], "LaunchGateImageProfileV1[3]") != PAGE_SIZE:
            _fail("PROFILE_PAGE_SIZE_INVALID", "image profile mapping size is not 4096")
        if _require_u64(values[9], "LaunchGateImageProfileV1[9]") != PAGE_SIZE:
            _fail("PROFILE_MAPPING_LENGTH_INVALID", "image profile mapping length is not 4096")
        if _require_u64(values[10], "LaunchGateImageProfileV1[10]") != 0:
            _fail("PROFILE_ENTRY_OFFSET_INVALID", "image profile entry offset is not zero")
        if _require_u64(values[12], "LaunchGateImageProfileV1[12]") != EMPTY_PATH_OFFSET:
            _fail("PROFILE_EMPTY_PATH_OFFSET_INVALID", "image profile empty-path offset is not 4095")
        return cls(
            base_length=_require_u64(values[4], "LaunchGateImageProfileV1[4]"),
            base_elf_sha256=_require_hash(values[5], "LaunchGateImageProfileV1[5]"),
            base_e_entry=_require_u64(values[6], "LaunchGateImageProfileV1[6]"),
            base_program_header_table_sha256=_require_hash(values[7], "LaunchGateImageProfileV1[7]"),
            gate_file_offset=_require_u64(values[8], "LaunchGateImageProfileV1[8]"),
            gate_code_size=_require_u64(values[11], "LaunchGateImageProfileV1[11]"),
            gate_code_sha256=_require_hash(values[13], "LaunchGateImageProfileV1[13]"),
            gate_page_sha256=_require_hash(values[14], "LaunchGateImageProfileV1[14]"),
            normalized_instruction_manifest_sha256=_require_hash(values[15], "LaunchGateImageProfileV1[15]"),
            normalized_cfg_manifest_sha256=_require_hash(values[16], "LaunchGateImageProfileV1[16]"),
            final_length=_require_u64(values[17], "LaunchGateImageProfileV1[17]"),
            final_image_sha256=_require_hash(values[18], "LaunchGateImageProfileV1[18]"),
        )


@dataclass(frozen=True, slots=True)
class SupervisorBuildProfileV1:
    """The literal fourteen-field SupervisorBuildProfileV1 wire record."""

    toolchain_manifest_sha256: bytes
    source_manifest_sha256: bytes
    build_command_manifest_sha256: bytes
    build_environment_manifest_sha256: bytes
    ordered_link_input_manifest_sha256: bytes
    validator_manifest_sha256: bytes
    launch_gate_source_sha256: bytes
    launch_gate_object_sha256: bytes
    launch_gate_page_sha256: bytes
    supervisor_base_sha256: bytes
    final_supervisor_image_sha256: bytes
    launch_gate_image_profile_sha256: bytes

    def __post_init__(self) -> None:
        for label, value in zip(
            (
                "toolchain_manifest_sha256",
                "source_manifest_sha256",
                "build_command_manifest_sha256",
                "build_environment_manifest_sha256",
                "ordered_link_input_manifest_sha256",
                "validator_manifest_sha256",
                "launch_gate_source_sha256",
                "launch_gate_object_sha256",
                "launch_gate_page_sha256",
                "supervisor_base_sha256",
                "final_supervisor_image_sha256",
                "launch_gate_image_profile_sha256",
            ),
            (
                self.toolchain_manifest_sha256,
                self.source_manifest_sha256,
                self.build_command_manifest_sha256,
                self.build_environment_manifest_sha256,
                self.ordered_link_input_manifest_sha256,
                self.validator_manifest_sha256,
                self.launch_gate_source_sha256,
                self.launch_gate_object_sha256,
                self.launch_gate_page_sha256,
                self.supervisor_base_sha256,
                self.final_supervisor_image_sha256,
                self.launch_gate_image_profile_sha256,
            ),
            strict=True,
        ):
            _require_hash(value, label)
        if self.launch_gate_object_sha256 != PINNED_GATE_OBJECT_SHA256:
            _fail(
                "PROFILE_GATE_OBJECT_HASH_INVALID",
                "supervisor profile does not bind the raw pre-extraction gate object",
            )
        if self.launch_gate_page_sha256 != PINNED_GATE_PAGE_SHA256:
            _fail(
                "PROFILE_GATE_PAGE_HASH_INVALID",
                "supervisor profile does not bind the corrected gate page",
            )

    def as_array(self) -> list[object]:
        return [
            PROTOCOL_ID,
            PROFILE_VERSION,
            self.toolchain_manifest_sha256,
            self.source_manifest_sha256,
            self.build_command_manifest_sha256,
            self.build_environment_manifest_sha256,
            self.ordered_link_input_manifest_sha256,
            self.validator_manifest_sha256,
            self.launch_gate_source_sha256,
            self.launch_gate_object_sha256,
            self.launch_gate_page_sha256,
            self.supervisor_base_sha256,
            self.final_supervisor_image_sha256,
            self.launch_gate_image_profile_sha256,
        ]

    def canonical_cbor(self) -> bytes:
        return canonical_cbor_encode(self.as_array())

    def sha256(self) -> bytes:
        return _sha256(self.canonical_cbor())

    @classmethod
    def from_canonical_cbor(cls, raw: object) -> "SupervisorBuildProfileV1":
        values = _require_exact_list(
            raw,
            label="SupervisorBuildProfileV1",
            count=SUPERVISOR_BUILD_PROFILE_FIELD_COUNT,
        )
        _assert_schema_prefix(values, label="SupervisorBuildProfileV1")
        return cls(*(_require_hash(value, f"SupervisorBuildProfileV1[{index}]") for index, value in enumerate(values[2:], 2)))


def build_launch_gate_image_profile(
    *,
    validated_trailer: LaunchGateTrailerValidationResultV1,
    base_elf: bytes,
    gate_page: bytes,
    final_image: bytes,
    decoder_agreement: LaunchGateDecoderAgreementResult,
) -> LaunchGateImageProfileV1:
    """Build the nineteen-field image profile from validated trailer evidence.

    The trailer result must already be valid.  This layer recomputes every
    Section-4 digest and fails closed if the supplied bytes do not exactly bind
    to that evidence.
    """

    if type(validated_trailer) is not LaunchGateTrailerValidationResultV1:
        _fail("PROFILE_TRAILER_RESULT_REQUIRED", "validated_trailer must be LaunchGateTrailerValidationResultV1")
    if not validated_trailer.valid or type(validated_trailer.evidence) is not LaunchGateTrailerEvidenceV1:
        _fail("PROFILE_TRAILER_NOT_VALIDATED", "validated_trailer must contain valid trailer evidence")
    evidence = validated_trailer.evidence
    base_elf = _require_bytes(base_elf, "base_elf")
    base_program_header_table = _derive_program_header_table(base_elf)
    gate_page = _require_bytes(gate_page, "gate_page")
    final_image = _require_bytes(final_image, "final_image")
    if type(decoder_agreement) is not LaunchGateDecoderAgreementResult:
        _fail(
            "PROFILE_DECODER_AGREEMENT_REQUIRED",
            "decoder_agreement must be the strict dual-decoder agreement result",
        )
    if (
        not decoder_agreement.valid
        or decoder_agreement.first is None
        or decoder_agreement.second is None
        or decoder_agreement.first.wrapper_bytes is None
        or decoder_agreement.second.wrapper_bytes is None
    ):
        _fail(
            "PROFILE_DECODER_AGREEMENT_INVALID",
            "both strict decoder outputs must be valid and byte-identical",
        )
    # Re-run the strict schema and equality boundary from the immutable output
    # bytes.  Caller-authored result fields are never accepted as profile input.
    rechecked = compare_launch_gate_decoder_outputs_v1(
        gate_page,
        decoder_agreement.first.wrapper_bytes,
        decoder_agreement.second.wrapper_bytes,
    )
    if (
        not rechecked.valid
        or rechecked.first is None
        or rechecked.second is None
        or rechecked.first.instruction_manifest_bytes is None
        or rechecked.first.cfg_manifest_bytes is None
    ):
        detail = rechecked.issues[0].code if rechecked.issues else "missing strict evidence"
        _fail(
            "PROFILE_DECODER_AGREEMENT_INVALID",
            f"strict dual-decoder revalidation failed: {detail}",
        )
    instruction_manifest = rechecked.first.instruction_manifest_bytes
    cfg_manifest = rechecked.first.cfg_manifest_bytes
    if len(base_elf) != evidence.base_length or _sha256(base_elf) != evidence.base_sha256:
        _fail("PROFILE_BASE_EVIDENCE_MISMATCH", "base ELF does not match validated trailer evidence")
    if _sha256(base_program_header_table) != evidence.base_program_header_table_sha256:
        _fail("PROFILE_PROGRAM_HEADER_EVIDENCE_MISMATCH", "program-header bytes do not match validated trailer evidence")
    if len(gate_page) != PAGE_SIZE:
        _fail("PROFILE_GATE_PAGE_SIZE_INVALID", "gate_page must be exactly 4096 bytes")
    if evidence.gate_code_size != PINNED_GATE_CODE_SIZE:
        _fail("PROFILE_GATE_CODE_SIZE_INVALID", "validated gate code size is not 874")
    if _sha256(gate_page[: evidence.gate_code_size]) != evidence.gate_code_sha256:
        _fail("PROFILE_GATE_CODE_EVIDENCE_MISMATCH", "gate code bytes do not match validated trailer evidence")
    if _sha256(gate_page) != evidence.gate_page_sha256:
        _fail("PROFILE_GATE_PAGE_EVIDENCE_MISMATCH", "gate page does not match validated trailer evidence")
    if evidence.gate_file_offset != _align_up(len(base_elf), PAGE_SIZE):
        _fail("PROFILE_GATE_OFFSET_EVIDENCE_MISMATCH", "validated gate offset is not aligned base length")
    if len(final_image) != evidence.final_length or _sha256(final_image) != evidence.final_sha256:
        _fail("PROFILE_FINAL_EVIDENCE_MISMATCH", "final image does not match validated trailer evidence")
    if len(final_image) != evidence.gate_file_offset + PAGE_SIZE:
        _fail("PROFILE_FINAL_LENGTH_INVALID", "final image is not exactly one aligned trailer page after base")
    if final_image[: len(base_elf)] != base_elf:
        _fail("PROFILE_BASE_PREFIX_MISMATCH", "final image does not preserve base ELF bytes")
    if final_image[len(base_elf) : evidence.gate_file_offset] != b"\x00" * (evidence.gate_file_offset - len(base_elf)):
        _fail("PROFILE_PADDING_INVALID", "trailer alignment bytes must be zero")
    if final_image[evidence.gate_file_offset :] != gate_page:
        _fail("PROFILE_GATE_TRAILER_MISMATCH", "final image trailer is not the supplied gate page")
    return LaunchGateImageProfileV1(
        base_length=len(base_elf),
        base_elf_sha256=_sha256(base_elf),
        base_e_entry=evidence.base_e_entry,
        base_program_header_table_sha256=_sha256(base_program_header_table),
        gate_file_offset=evidence.gate_file_offset,
        gate_code_size=evidence.gate_code_size,
        gate_code_sha256=_sha256(gate_page[: evidence.gate_code_size]),
        gate_page_sha256=_sha256(gate_page),
        normalized_instruction_manifest_sha256=_sha256(instruction_manifest),
        normalized_cfg_manifest_sha256=_sha256(cfg_manifest),
        final_length=len(final_image),
        final_image_sha256=_sha256(final_image),
    )


def build_supervisor_build_profile(
    *,
    toolchain_manifest_cbor: bytes,
    source_manifest_cbor: bytes,
    build_command_manifest_cbor: bytes,
    build_environment_manifest_cbor: bytes,
    ordered_link_input_manifest_cbor: bytes,
    validator_manifest_cbor: bytes,
    launch_gate_source: bytes,
    launch_gate_object: bytes,
    launch_gate_page: bytes,
    supervisor_base: bytes,
    final_supervisor_image: bytes,
    launch_gate_image_profile: LaunchGateImageProfileV1,
) -> SupervisorBuildProfileV1:
    """Build the frozen supervisor profile from exact, already-owned bytes."""

    manifests = tuple(
        validate_restricted_canonical_cbor(raw, label=label)
        for label, raw in (
            ("toolchain_manifest_cbor", toolchain_manifest_cbor),
            ("source_manifest_cbor", source_manifest_cbor),
            ("build_command_manifest_cbor", build_command_manifest_cbor),
            ("build_environment_manifest_cbor", build_environment_manifest_cbor),
            ("ordered_link_input_manifest_cbor", ordered_link_input_manifest_cbor),
            ("validator_manifest_cbor", validator_manifest_cbor),
        )
    )
    if type(launch_gate_image_profile) is not LaunchGateImageProfileV1:
        _fail("PROFILE_IMAGE_PROFILE_REQUIRED", "launch_gate_image_profile must be LaunchGateImageProfileV1")
    artifacts = tuple(
        _require_bytes(raw, label)
        for label, raw in (
            ("launch_gate_source", launch_gate_source),
            ("launch_gate_object", launch_gate_object),
            ("launch_gate_page", launch_gate_page),
            ("supervisor_base", supervisor_base),
            ("final_supervisor_image", final_supervisor_image),
        )
    )
    if (
        len(artifacts[1]) != PINNED_GATE_OBJECT_SIZE
        or _sha256(artifacts[1]) != PINNED_GATE_OBJECT_SHA256
    ):
        _fail(
            "PROFILE_BUILD_GATE_OBJECT_MISMATCH",
            "build gate object is not the raw pre-extraction pinned object",
        )
    if len(artifacts[2]) != PAGE_SIZE or _sha256(artifacts[2]) != PINNED_GATE_PAGE_SHA256:
        _fail(
            "PROFILE_BUILD_GATE_PAGE_MISMATCH",
            "build gate page is not the corrected pinned page",
        )
    if _sha256(artifacts[2]) != launch_gate_image_profile.gate_page_sha256:
        _fail("PROFILE_BUILD_GATE_PAGE_MISMATCH", "build gate page does not match image profile")
    if _sha256(artifacts[3]) != launch_gate_image_profile.base_elf_sha256:
        _fail("PROFILE_BUILD_BASE_MISMATCH", "build base does not match image profile")
    if _sha256(artifacts[4]) != launch_gate_image_profile.final_image_sha256:
        _fail("PROFILE_BUILD_FINAL_MISMATCH", "build final image does not match image profile")
    return SupervisorBuildProfileV1(
        *(_sha256(manifest) for manifest in manifests),
        *(_sha256(artifact) for artifact in artifacts),
        launch_gate_image_profile.sha256(),
    )


__all__ = [
    "AGENT_MODIFICATION_AUTHORIZED",
    "AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORIZED",
    "EM_X86_64",
    "EMPTY_PATH_OFFSET",
    "HOLDOUT_ACCESS_AUTHORIZED",
    "LAUNCH_GATE_IMAGE_PROFILE_FIELD_COUNT",
    "LaunchGateImageProfileV1",
    "LaunchGateStage1ProfileError",
    "NO_UPLOAD",
    "PAGE_SIZE",
    "PINNED_GATE_CODE_SIZE",
    "PINNED_GATE_OBJECT_SHA256",
    "PINNED_GATE_OBJECT_SIZE",
    "PINNED_GATE_PAGE_SHA256",
    "PERMIT_AUTHORITY",
    "PRODUCTION_UPLOAD_AUTHORIZED",
    "PROFILE_VERSION",
    "PROTOCOL_ID",
    "SHA256_SIZE",
    "SUPERVISOR_BUILD_PROFILE_FIELD_COUNT",
    "SupervisorBuildProfileV1",
    "ZERO_AUTHORITY",
    "build_launch_gate_image_profile",
    "build_supervisor_build_profile",
    "validate_restricted_canonical_cbor",
]
