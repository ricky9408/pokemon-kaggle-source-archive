"""Pure Stage-1 LaunchGateV1 trailer packer.

This module performs only the frozen append-only byte operation.  It does not
parse ELF, validate instructions, inspect host state, or provide campaign,
permit, upload, holdout, or agent-modification authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Final, Iterator, Mapping


PAGE_SIZE: Final = 4096
END_BR64: Final = b"\xf3\x0f\x1e\xfa"
PADDING_BYTE: Final = 0xCC
EMPTY_PATH_OFFSET: Final = PAGE_SIZE - 1
STAGE1_SCHEMA: Final = "eval.v6.3.1.stage1.launch-gate-append-only-trailer.v1"
BINDING_LABEL: Final = "V631302_STAGE1_AUTHENTICATED_TRAILER_LAUNCH_GATE_FREEZE_1"

# These are deliberately constants, rather than caller-provided metadata.
NO_UPLOAD: Final = "NO_UPLOAD"
AUTHORITY: Final = False
ENGINE_WIRING_AUTHORITY: Final = False
UPLOAD_AUTHORITY: Final = False
HOLDOUT_ACCESS_AUTHORITY: Final = False
CALIBRATION_UPLOAD_AUTHORIZED: Final = False
PRODUCTION_UPLOAD_AUTHORIZED: Final = False
SEALED_HOLDOUT_ACCESS_AUTHORIZED: Final = False
AGENT_MODIFICATION_AUTHORIZED: Final = False
AGENT_MODIFICATION_AUTHORITY: Final = False
PERMIT_AUTHORITY: Final = False
ZERO_AUTHORITY: Final = True


class Stage1PackerError(ValueError):
    """A malformed Stage-1 byte input, reported with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True, slots=True)
class Stage1PackResult:
    """Immutable packed bytes and immutable, descriptive pack metadata."""

    final_image: bytes
    metadata: Mapping[str, object]

    @property
    def image(self) -> bytes:
        """Return the packed image bytes."""

        return self.final_image

    def __iter__(self) -> Iterator[object]:
        """Allow convenient ``image, metadata = pack_stage1_trailer(...)``."""

        yield self.final_image
        yield self.metadata


def _as_bytes(value: object, *, name: str) -> bytes:
    if type(value) is bytes:
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            # Read through the buffer protocol so a bytes subclass cannot
            # override len, slicing, concatenation, or __bytes__ semantics.
            return memoryview(value).tobytes()
        except (BufferError, TypeError, ValueError) as exc:
            raise Stage1PackerError("INPUT_BYTES_INVALID", f"{name} is not readable bytes: {exc}") from exc
    raise Stage1PackerError("INPUT_BYTES_INVALID", f"{name} must be bytes-like")


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _digest(value: bytes) -> str:
    return sha256(value).hexdigest()


def pack_stage1_trailer(
    base_bytes: bytes | bytearray | memoryview,
    gate_page: bytes | bytearray | memoryview,
    gate_code_size: int,
) -> Stage1PackResult:
    """Append one validated 4096-byte gate page to exact base bytes.

    ``base_bytes`` is copied once and is never parsed or rewritten.  The gate
    starts at ``align_up(len(base_bytes), 4096)``; bytes between the base and
    that offset are newly-created zero padding.  The returned metadata is a
    read-only mapping and all authority fields are fixed to zero-authority
    values by this module.
    """

    base = _as_bytes(base_bytes, name="base_bytes")
    page = _as_bytes(gate_page, name="gate_page")

    if len(page) != PAGE_SIZE:
        raise Stage1PackerError("GATE_PAGE_SIZE_INVALID", "gate_page must be exactly 4096 bytes")
    if type(gate_code_size) is not int:
        raise Stage1PackerError("GATE_CODE_SIZE_INVALID", "gate_code_size must be an integer")
    if not 4 <= gate_code_size <= EMPTY_PATH_OFFSET:
        raise Stage1PackerError(
            "GATE_CODE_SIZE_INVALID",
            "gate_code_size must include endbr64 and leave the final NUL byte reserved",
        )
    if page[: len(END_BR64)] != END_BR64:
        raise Stage1PackerError("GATE_ENTRY_INVALID", "gate page must begin with endbr64")
    if page[gate_code_size:EMPTY_PATH_OFFSET] != bytes([PADDING_BYTE]) * (
        EMPTY_PATH_OFFSET - gate_code_size
    ):
        raise Stage1PackerError("GATE_PADDING_INVALID", "gate bytes after code must be 0xCC padding")
    if page[EMPTY_PATH_OFFSET] != 0:
        raise Stage1PackerError("GATE_EMPTY_PATH_INVALID", "gate page offset 4095 must be NUL")

    gate_file_offset = _align_up(len(base), PAGE_SIZE)
    padding_length = gate_file_offset - len(base)
    padding = b"\x00" * padding_length
    final_image = base + padding + page

    metadata = MappingProxyType(
        {
            "schema": STAGE1_SCHEMA,
            "binding_label": BINDING_LABEL,
            "base_length": len(base),
            "base_sha256": _digest(base),
            "gate_file_offset": gate_file_offset,
            "padding_length": padding_length,
            "padding_sha256": _digest(padding),
            "gate_mapping_length": PAGE_SIZE,
            "gate_entry_offset": 0,
            "gate_code_size": gate_code_size,
            "empty_path_offset": EMPTY_PATH_OFFSET,
            "gate_code_sha256": _digest(page[:gate_code_size]),
            "gate_page_sha256": _digest(page),
            "final_length": len(final_image),
            "final_image_sha256": _digest(final_image),
            "authority": AUTHORITY,
            "zero_authority": ZERO_AUTHORITY,
            "engine_wiring_authority": ENGINE_WIRING_AUTHORITY,
            "upload_authority": UPLOAD_AUTHORITY,
            "holdout_access_authority": HOLDOUT_ACCESS_AUTHORITY,
            "state": NO_UPLOAD,
            "calibration_upload_authorized": CALIBRATION_UPLOAD_AUTHORIZED,
            "production_upload_authorized": PRODUCTION_UPLOAD_AUTHORIZED,
            "sealed_holdout_access_authorized": SEALED_HOLDOUT_ACCESS_AUTHORIZED,
            "agent_modification_authorized": AGENT_MODIFICATION_AUTHORIZED,
            "agent_modification_authority": AGENT_MODIFICATION_AUTHORITY,
            "permit_authority": PERMIT_AUTHORITY,
        }
    )
    return Stage1PackResult(final_image=final_image, metadata=metadata)


pack_launch_gate_stage1 = pack_stage1_trailer
pack_stage1_append_only = pack_stage1_trailer


__all__ = [
    "AGENT_MODIFICATION_AUTHORIZED",
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "BINDING_LABEL",
    "CALIBRATION_UPLOAD_AUTHORIZED",
    "ENGINE_WIRING_AUTHORITY",
    "EMPTY_PATH_OFFSET",
    "END_BR64",
    "NO_UPLOAD",
    "PAGE_SIZE",
    "PERMIT_AUTHORITY",
    "PADDING_BYTE",
    "PRODUCTION_UPLOAD_AUTHORIZED",
    "SEALED_HOLDOUT_ACCESS_AUTHORIZED",
    "STAGE1_SCHEMA",
    "Stage1PackResult",
    "Stage1PackerError",
    "HOLDOUT_ACCESS_AUTHORITY",
    "UPLOAD_AUTHORITY",
    "ZERO_AUTHORITY",
    "pack_launch_gate_stage1",
    "pack_stage1_append_only",
    "pack_stage1_trailer",
]
