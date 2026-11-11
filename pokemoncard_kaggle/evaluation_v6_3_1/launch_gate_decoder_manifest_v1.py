"""Strict, zero-authority validation of the Stage-1 decoder wire format.

This is the third-party schema boundary described by
``V631302_STAGE1_DUAL_DECODER_CANONICAL_WIRE_ERRATUM_1``.  It consumes only a
gate page and completed decoder-output bytes.  It does not decode x86, invoke
either decoder, read the other decoder's output, execute a process, or create
campaign, holdout, agent-modification, permit, or upload authority.

The CBOR implementation is intentionally local to this module.  It supports
only the arrays, byte strings, and signed integers admitted by the wire
contract and rejects every other CBOR major type.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Final, Sequence


PROTOCOL_ID: Final = 631302
WIRE_VERSION: Final = 1
GATE_PAGE_SIZE: Final = 4096
GATE_CODE_SIZE: Final = 874
GATE_PAGE_SHA256: Final = bytes.fromhex(
    "91fce3ca09e908b9e51d73e887f67a14ba7b5c250180cb613f871666f12277f5"
)

ZERO_AUTHORITY: Final = True
AUTHORITY: Final = False
CALIBRATION_UPLOAD_AUTHORITY: Final = False
PRODUCTION_UPLOAD_AUTHORITY: Final = False
SEALED_HOLDOUT_ACCESS_AUTHORITY: Final = False
AGENT_MODIFICATION_AUTHORITY: Final = False

# Stable issue codes.  The validator reports the first deterministic failure;
# callers must not interpret a successful structural result as authority.
CBOR_INPUT_INVALID: Final = "DECODER_MANIFEST_CBOR_INPUT_INVALID"
CBOR_NONCANONICAL: Final = "DECODER_MANIFEST_CBOR_NONCANONICAL"
CBOR_FORBIDDEN_TYPE: Final = "DECODER_MANIFEST_CBOR_FORBIDDEN_TYPE"
CBOR_LIMIT: Final = "DECODER_MANIFEST_CBOR_LIMIT"
WRAPPER_INVALID: Final = "DECODER_MANIFEST_WRAPPER_INVALID"
PAGE_INVALID: Final = "DECODER_MANIFEST_PAGE_INVALID"
PAGE_HASH_MISMATCH: Final = "DECODER_MANIFEST_PAGE_HASH_MISMATCH"
INSTRUCTION_INVALID: Final = "DECODER_MANIFEST_INSTRUCTION_INVALID"
OPERAND_INVALID: Final = "DECODER_MANIFEST_OPERAND_INVALID"
ATTRIBUTE_INVALID: Final = "DECODER_MANIFEST_ATTRIBUTE_INVALID"
RAW_BYTES_INVALID: Final = "DECODER_MANIFEST_RAW_BYTES_INVALID"
CFG_INVALID: Final = "DECODER_MANIFEST_CFG_INVALID"
HASH_INVALID: Final = "DECODER_MANIFEST_HASH_INVALID"
OUTPUT_BYTE_MISMATCH: Final = "DECODER_MANIFEST_OUTPUT_BYTE_MISMATCH"
OUTPUT_INPUT_INVALID: Final = "DECODER_MANIFEST_OUTPUT_INPUT_INVALID"

_UINT64_MAX = (1 << 64) - 1
_MAX_DEPTH = 64
_MAX_NODES = 200_000
_MAX_ITEMS = 100_000
_MAX_BYTES = 16 * 1024 * 1024
_KNOWN_ATTRIBUTES = (1 << 21) - 1
_KNOWN_FLAGS = 0x3F
_GPR64 = frozenset(range(1, 17))
_GPR32 = frozenset(range(18, 34))
_GPR16 = frozenset(range(34, 50))
_GPR8 = frozenset(range(50, 66))
_REGISTERS = _GPR64 | _GPR32 | _GPR16 | _GPR8 | {17}
_WIDTHS = frozenset((8, 16, 32, 64))
_ACCESS_EXPLICIT = frozenset((1, 2, 3))
_ACCESS_READ = 1
_ACCESS_WRITE = 2
_ACCESS_READ_WRITE = 3
_ACCESS_CLOBBER = 4
_CONDITIONS = frozenset((2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15))
_CONDITION_FLAGS = {
    2: 1,
    3: 1,
    4: 8,
    5: 8,
    6: 1 | 8,
    7: 1 | 8,
    8: 16,
    9: 16,
    12: 16 | 32,
    13: 16 | 32,
    14: 8 | 16 | 32,
    15: 8 | 16 | 32,
}
_MODRM_ONE_BYTE_OPCODES = frozenset(
    (
        0x30,
        0x31,
        0x32,
        0x33,
        0x38,
        0x39,
        0x3A,
        0x3B,
        0x80,
        0x81,
        0x83,
        0x84,
        0x85,
        0x88,
        0x89,
        0x8A,
        0x8B,
        0x8D,
        0xC6,
        0xC7,
        0xF6,
        0xF7,
    )
)
_NO_MODRM_ONE_BYTE_OPCODES = frozenset((0x3C, 0x3D, 0xA8, 0xA9)) | frozenset(range(0xB0, 0xC0))


class LaunchGateDecoderManifestError(ValueError):
    """One stable, fail-closed schema error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class LaunchGateDecoderManifestIssue:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class LaunchGateDecoderManifestValidationResult:
    valid: bool
    issues: tuple[LaunchGateDecoderManifestIssue, ...]
    wrapper_bytes: bytes | None = None
    instruction_manifest_bytes: bytes | None = None
    cfg_manifest_bytes: bytes | None = None
    instruction_manifest_sha256: bytes | None = None
    cfg_manifest_sha256: bytes | None = None
    wrapper_sha256: bytes | None = None
    authority: bool = False
    calibration_upload_authority: bool = False
    production_upload_authority: bool = False
    sealed_holdout_access_authority: bool = False
    agent_modification_authority: bool = False

    @property
    def zero_authority(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class LaunchGateDecoderAgreementResult:
    valid: bool
    issues: tuple[LaunchGateDecoderManifestIssue, ...]
    first: LaunchGateDecoderManifestValidationResult | None = None
    second: LaunchGateDecoderManifestValidationResult | None = None
    authority: bool = False
    calibration_upload_authority: bool = False
    production_upload_authority: bool = False
    sealed_holdout_access_authority: bool = False
    agent_modification_authority: bool = False

    @property
    def zero_authority(self) -> bool:
        return True


def _fail(code: str, message: str) -> None:
    raise LaunchGateDecoderManifestError(code, message)


def _head(major: int, value: int) -> bytes:
    if type(value) is not int or value < 0 or value > _UINT64_MAX:
        _fail(CBOR_NONCANONICAL, "CBOR argument is outside uint64")
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 0xFF:
        return bytes(((major << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")


def encode_canonical_cbor_v1(value: Any) -> bytes:
    """Encode the arrays-only, byte-string/integer CBOR subset independently."""

    active: set[int] = set()
    nodes = 0

    def encode(item: Any, depth: int) -> bytes:
        nonlocal nodes
        if depth > _MAX_DEPTH:
            _fail(CBOR_LIMIT, "CBOR nesting limit exceeded")
        nodes += 1
        if nodes > _MAX_NODES:
            _fail(CBOR_LIMIT, "CBOR node limit exceeded")
        if type(item) is int:
            if item >= 0:
                return _head(0, item)
            magnitude = -1 - item
            return _head(1, magnitude)
        if type(item) is bytes:
            if len(item) > _MAX_BYTES:
                _fail(CBOR_LIMIT, "byte string exceeds the CBOR limit")
            return _head(2, len(item)) + item
        if type(item) is list:
            if len(item) > _MAX_ITEMS:
                _fail(CBOR_LIMIT, "array exceeds the CBOR item limit")
            identity = id(item)
            if identity in active:
                _fail(CBOR_NONCANONICAL, "cyclic array")
            active.add(identity)
            try:
                encoded = b"".join(encode(child, depth + 1) for child in item)
            finally:
                active.remove(identity)
            result = _head(4, len(item)) + encoded
            if len(result) > _MAX_BYTES:
                _fail(CBOR_LIMIT, "encoded value exceeds the CBOR limit")
            return result
        _fail(CBOR_FORBIDDEN_TYPE, "wire CBOR admits only lists, bytes, and integers")
        raise AssertionError  # pragma: no cover

    result = encode(value, 0)
    if len(result) > _MAX_BYTES:
        _fail(CBOR_LIMIT, "encoded value exceeds the CBOR limit")
    return result


class _CanonicalDecoder:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0
        self.nodes = 0

    def take(self, count: int) -> bytes:
        end = self.offset + count
        if count < 0 or end > len(self.raw):
            _fail(CBOR_NONCANONICAL, "truncated CBOR item")
        value = self.raw[self.offset:end]
        self.offset = end
        return value

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if width is None:
            _fail(CBOR_NONCANONICAL, "indefinite or reserved CBOR argument")
        value = int.from_bytes(self.take(width), "big")
        minimum = {1: 24, 2: 256, 4: 65536, 8: 1 << 32}[width]
        if value < minimum:
            _fail(CBOR_NONCANONICAL, "CBOR argument is not minimally encoded")
        return value

    def value(self, depth: int = 0) -> Any:
        if depth > _MAX_DEPTH:
            _fail(CBOR_LIMIT, "CBOR nesting limit exceeded")
        self.nodes += 1
        if self.nodes > _MAX_NODES:
            _fail(CBOR_LIMIT, "CBOR node limit exceeded")
        initial = self.take(1)[0]
        major, additional = initial >> 5, initial & 0x1F
        if major in (0, 1):
            argument = self.argument(additional)
            return argument if major == 0 else -1 - argument
        if major == 2:
            length = self.argument(additional)
            if length > _MAX_BYTES:
                _fail(CBOR_LIMIT, "byte string exceeds the CBOR limit")
            return self.take(length)
        if major == 4:
            length = self.argument(additional)
            if length > _MAX_ITEMS:
                _fail(CBOR_LIMIT, "array exceeds the CBOR item limit")
            return [self.value(depth + 1) for _ in range(length)]
        if major in (3, 5, 6, 7):
            _fail(CBOR_FORBIDDEN_TYPE, "text, map, tag, float, boolean, and null are forbidden")
        _fail(CBOR_FORBIDDEN_TYPE, "unsupported CBOR major type")
        raise AssertionError  # pragma: no cover


def decode_canonical_cbor_v1(raw: bytes) -> Any:
    """Decode exactly one canonical arrays-only CBOR value."""

    if type(raw) is not bytes:
        _fail(CBOR_INPUT_INVALID, "decoder output must be bytes")
    if not raw or len(raw) > _MAX_BYTES:
        _fail(CBOR_INPUT_INVALID, "decoder output has an invalid byte length")
    decoder = _CanonicalDecoder(raw)
    value = decoder.value()
    if decoder.offset != len(raw):
        _fail(CBOR_NONCANONICAL, "trailing decoder-output bytes")
    if encode_canonical_cbor_v1(value) != raw:
        _fail(CBOR_NONCANONICAL, "decoder output is not minimally encoded")
    return value


def _array(value: Any, label: str, length: int | None = None) -> list[Any]:
    if type(value) is not list:
        _fail(INSTRUCTION_INVALID, f"{label} must be an array")
    if length is not None and len(value) != length:
        _fail(INSTRUCTION_INVALID, f"{label} must have length {length}")
    return value


def _uint(value: Any, label: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0:
        _fail(INSTRUCTION_INVALID, f"{label} must be unsigned")
    if maximum is not None and value > maximum:
        _fail(INSTRUCTION_INVALID, f"{label} exceeds its closed range")
    return value


def _sint(value: Any, label: str) -> int:
    if type(value) is not int:
        _fail(OPERAND_INVALID, f"{label} must be a mathematical integer")
    return value


def _bytes(value: Any, label: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        _fail(OPERAND_INVALID, f"{label} must be a byte string")
    if length is not None and len(value) != length:
        _fail(OPERAND_INVALID, f"{label} must have length {length}")
    return value


def _register(value: Any, label: str, *, explicit: bool = False) -> int:
    register = _uint(value, label, 65)
    if register not in _REGISTERS:
        _fail(OPERAND_INVALID, f"{label} is not a closed register ID")
    if explicit and register == 17:
        _fail(OPERAND_INVALID, "RIP is not an explicit register operand")
    return register


def _register_width(register: int) -> int:
    if register in _GPR64 or register == 17:
        return 64
    if register in _GPR32:
        return 32
    if register in _GPR16:
        return 16
    if register in _GPR8:
        return 8
    _fail(OPERAND_INVALID, "unknown register width")
    raise AssertionError


def _parent64(register: int) -> int:
    if register in _GPR32:
        return register - 17
    if register in _GPR16:
        return register - 33
    if register in _GPR8:
        return register - 49
    _fail(OPERAND_INVALID, "register has no 64-bit parent")
    raise AssertionError


def _reg_operand(value: Any, label: str, *, explicit: bool) -> tuple[int, int, int]:
    row = _array(value, label, 3)
    if row[0] != 0:
        _fail(OPERAND_INVALID, f"{label} is not a register operand")
    register = _register(row[1], f"{label}.register", explicit=explicit)
    access = _uint(row[2], f"{label}.access", 4)
    if explicit and access not in _ACCESS_EXPLICIT:
        _fail(OPERAND_INVALID, f"{label} has an invalid explicit access")
    if not explicit and access not in (_ACCESS_READ, _ACCESS_WRITE, _ACCESS_CLOBBER):
        _fail(OPERAND_INVALID, f"{label} has an invalid implicit access")
    return register, access, _register_width(register)


def _immediate(value: Any, label: str) -> tuple[int, int, int, int, int, bytes, bytes]:
    row = _array(value, label, 7)
    if row[0] != 1:
        _fail(OPERAND_INVALID, f"{label} is not an immediate")
    encoded_width = _uint(row[1], f"{label}.encoded_width")
    semantic_width = _uint(row[2], f"{label}.semantic_width")
    if encoded_width not in _WIDTHS or semantic_width not in _WIDTHS:
        _fail(OPERAND_INVALID, f"{label} has a forbidden immediate width")
    signedness = _uint(row[3], f"{label}.signedness", 1)
    extension = _uint(row[4], f"{label}.extension", 2)
    encoded = _bytes(row[5], f"{label}.encoded_bytes", encoded_width // 8)
    semantic = _bytes(row[6], f"{label}.semantic_bytes", semantic_width // 8)
    if extension == 0:
        if encoded_width != semantic_width or encoded != semantic or signedness != 0:
            _fail(OPERAND_INVALID, f"{label} has an invalid no-extension value")
    elif extension == 1:
        if semantic_width <= encoded_width or signedness != 1:
            _fail(OPERAND_INVALID, f"{label} has an invalid sign extension declaration")
        sign = encoded[-1] & 0x80
        expected = encoded + ((b"\xff" if sign else b"\x00") * ((semantic_width - encoded_width) // 8))
        if semantic != expected:
            _fail(OPERAND_INVALID, f"{label} is not exact two's-complement sign extension")
    else:
        if semantic_width <= encoded_width or signedness != 0:
            _fail(OPERAND_INVALID, f"{label} has an invalid zero extension declaration")
        if semantic != encoded + b"\x00" * ((semantic_width - encoded_width) // 8):
            _fail(OPERAND_INVALID, f"{label} is not exact zero extension")
    return encoded_width, semantic_width, signedness, extension, len(encoded), encoded, semantic


def _branch(value: Any, label: str) -> tuple[int, int, int, int]:
    row = _array(value, label, 4)
    if row[0] != 2:
        _fail(OPERAND_INVALID, f"{label} is not a direct branch operand")
    width = _uint(row[1], f"{label}.width")
    if width not in (8, 32):
        _fail(OPERAND_INVALID, f"{label} has a forbidden displacement width")
    displacement = _sint(row[2], f"{label}.displacement")
    limit = 1 << (width - 1)
    if not -limit <= displacement < limit:
        _fail(OPERAND_INVALID, f"{label}.displacement is outside its signed width")
    target = _uint(row[3], f"{label}.target", GATE_CODE_SIZE - 1)
    return width, displacement, target, width // 8


def _address_parts(
    value: Any,
    label: str,
    *,
    memory: bool,
    allow_stack: bool = False,
    instruction_offset: int | None = None,
    instruction_length: int | None = None,
) -> tuple[Any, ...]:
    expected = 12 if memory else 10
    row = _array(value, label, expected)
    base_index = 4 if memory else 2
    if memory:
        if row[0] != 3:
            _fail(OPERAND_INVALID, f"{label} is not a memory operand")
        access = _uint(row[1], f"{label}.access", 3)
        value_width = _uint(row[2], f"{label}.value_width")
        if value_width not in _WIDTHS:
            _fail(OPERAND_INVALID, f"{label} has a forbidden value width")
        address_width = _uint(row[3], f"{label}.address_width")
        base = row[4]
        index = row[5]
        scale = row[6]
        displacement_width = row[7]
        displacement = row[8]
        rip_target = row[9]
        provenance = row[10]
        provenance_offset = row[11]
    else:
        if row[0] != 4:
            _fail(OPERAND_INVALID, f"{label} is not an address operand")
        access = None
        value_width = None
        address_width = row[1]
        base = row[2]
        index = row[3]
        scale = row[4]
        displacement_width = row[5]
        displacement = row[6]
        rip_target = row[7]
        provenance = row[8]
        provenance_offset = row[9]
    if address_width != 64:
        _fail(OPERAND_INVALID, f"{label} address width must be 64")
    base = _register(base, f"{label}.base")
    if base not in _GPR64 and base != 17:
        _fail(OPERAND_INVALID, f"{label}.base must be a 64-bit register")
    index = _uint(index, f"{label}.index", 65)
    if index != 0 and index not in _GPR64:
        _fail(OPERAND_INVALID, f"{label}.index must be zero or a 64-bit GPR")
    if index == 5:
        _fail(OPERAND_INVALID, f"{label}.index may not be RSP")
    scale = _uint(scale, f"{label}.scale")
    if scale not in (1, 2, 4, 8) or (index == 0 and scale != 1):
        _fail(OPERAND_INVALID, f"{label}.scale is inconsistent with its index")
    displacement_width = _uint(displacement_width, f"{label}.displacement_width")
    if displacement_width not in (0, 8, 32):
        _fail(OPERAND_INVALID, f"{label}.displacement_width is forbidden")
    displacement = _sint(displacement, f"{label}.displacement")
    if displacement_width == 0 and displacement != 0:
        _fail(OPERAND_INVALID, f"{label} has a nonzero unencoded displacement")
    if displacement_width:
        limit = 1 << (displacement_width - 1)
        if not -limit <= displacement < limit:
            _fail(OPERAND_INVALID, f"{label}.displacement is outside its encoded width")
    rip_target = _sint(rip_target, f"{label}.rip_target")
    if base == 17:
        if instruction_offset is None or instruction_length is None:
            _fail(OPERAND_INVALID, f"{label} lacks an instruction context for RIP resolution")
        expected_rip = instruction_offset + instruction_length + displacement
        if rip_target != expected_rip or not 0 <= expected_rip <= GATE_PAGE_SIZE - 1:
            _fail(OPERAND_INVALID, f"{label}.rip_target is outside the page")
    elif rip_target != -1:
        _fail(OPERAND_INVALID, f"{label}.rip_target must be -1 for non-RIP addressing")
    provenance = _uint(provenance, f"{label}.provenance")
    if provenance not in (1, 2, 3, 4, 5):
        _fail(OPERAND_INVALID, f"{label}.provenance is not an allowed provenance ID")
    provenance_offset = _uint(provenance_offset, f"{label}.provenance_offset")
    if provenance in (1, 2, 3):
        size = {1: 64, 2: 48, 3: 88}[provenance]
        if provenance_offset + ((value_width or 0) // 8 if memory else 0) > size:
            _fail(OPERAND_INVALID, f"{label}.provenance range exceeds its record")
        if not memory and provenance_offset > size:
            _fail(OPERAND_INVALID, f"{label}.provenance offset exceeds its record")
    elif provenance == 4:
        if memory or base != 17 or index != 0 or scale != 1 or provenance_offset != rip_target or provenance_offset != 4095:
            _fail(OPERAND_INVALID, f"{label} has invalid gate-page provenance")
    elif provenance == 5:
        if not (
            allow_stack
            and memory
            and access == _ACCESS_READ
            and base == 5
            and index == 0
            and scale == 1
            and displacement_width == 0
            and displacement == 0
            and rip_target == -1
            and provenance_offset == 0
            and value_width == 64
        ):
            _fail(OPERAND_INVALID, f"{label} may not use stack provenance")
    return (access, value_width, address_width, base, index, scale, displacement_width, displacement, rip_target, provenance, provenance_offset)


def _validate_operand(
    value: Any,
    label: str,
    *,
    explicit: bool,
    instruction_offset: int | None = None,
    instruction_length: int | None = None,
) -> tuple[int, int | None]:
    row = _array(value, label)
    if not row:
        _fail(OPERAND_INVALID, f"{label} is empty")
    tag = _uint(row[0], f"{label}.tag", 4)
    if tag == 0:
        register, access, width = _reg_operand(row, label, explicit=explicit)
        if not explicit and register == 17 and access != _ACCESS_WRITE:
            _fail(OPERAND_INVALID, "RIP is only an implicit branch/return write")
        return tag, width
    if tag == 1:
        if not explicit:
            _fail(OPERAND_INVALID, "immediate is never an implicit operand")
        return tag, _immediate(row, label)[1]
    if tag == 2:
        if not explicit:
            _fail(OPERAND_INVALID, "branch is never an implicit operand")
        return tag, None
    if tag == 3:
        parts = _address_parts(row, label, memory=True, instruction_offset=instruction_offset, instruction_length=instruction_length)
        return tag, parts[1]
    if not explicit:
        _fail(OPERAND_INVALID, "address-only expression is never implicit")
    parts = _address_parts(row, label, memory=False, instruction_offset=instruction_offset, instruction_length=instruction_length)
    return tag, None


def _implicit_rows(
    value: Any,
    label: str,
    *,
    allow_stack: bool = False,
    instruction_offset: int | None = None,
    instruction_length: int | None = None,
) -> list[list[Any]]:
    rows = _array(value, label)
    for index, row in enumerate(rows):
        _reg_or_memory_implicit(
            row,
            f"{label}[{index}]",
            allow_stack=allow_stack,
            instruction_offset=instruction_offset,
            instruction_length=instruction_length,
        )
    return rows


def _reg_or_memory_implicit(
    value: Any,
    label: str,
    *,
    allow_stack: bool = False,
    instruction_offset: int | None = None,
    instruction_length: int | None = None,
) -> None:
    row = _array(value, label)
    if row and row[0] == 0:
        _reg_operand(row, label, explicit=False)
        return
    if row and row[0] == 3:
        parts = _address_parts(
            row,
            label,
            memory=True,
            allow_stack=allow_stack,
            instruction_offset=instruction_offset,
            instruction_length=instruction_length,
        )
        if parts[0] != _ACCESS_READ:
            _fail(OPERAND_INVALID, f"{label} implicit memory access must be a read")
        return
    _fail(OPERAND_INVALID, f"{label} is not a register or memory operand")


def _exact_implicit(value: Any, expected: list[list[Any]], label: str) -> None:
    if value != expected:
        _fail(OPERAND_INVALID, f"{label} does not match its closed implicit contract")


def _expected_parent_writes(opcode: int, explicit: list[Any], current: list[Any], attribute: int) -> None:
    destination: int | None = None
    if opcode in (2, 3):
        destination = _reg_operand(explicit[0], "destination", explicit=True)[0] if opcode == 2 and explicit[0][0] == 0 else (
            _reg_operand(explicit[0], "destination", explicit=True)[0] if opcode == 3 else None
        )
    elif opcode == 4:
        destination = _reg_operand(explicit[0], "xor.left", explicit=True)[0]
    if destination in _GPR32:
        expected = [[0, _parent64(destination), 2]]
        if current != expected or not attribute & (1 << 16):
            _fail(OPERAND_INVALID, "32-bit destination lacks its parent write")
    elif destination is not None and (destination in _GPR8 or destination in _GPR16):
        if current:
            _fail(OPERAND_INVALID, "8/16-bit destination has an invalid parent write")
    elif destination is not None and current:
        _fail(OPERAND_INVALID, "64-bit destination has an unexpected parent write")


def _raw_modrm_and_sib(opcode: int, raw: bytes) -> tuple[bool, bool]:
    """Derive the ModRM/SIB presence bits from the exact instruction bytes."""

    if opcode == 1:
        return True, False
    if opcode in (7, 8, 9, 10):
        return False, False

    cursor = 1 if raw and 0x40 <= raw[0] <= 0x4F else 0
    if cursor >= len(raw):
        _fail(RAW_BYTES_INVALID, "instruction has no opcode byte")
    first_opcode = raw[cursor]
    cursor += 1
    if first_opcode == 0x0F:
        if cursor >= len(raw):
            _fail(RAW_BYTES_INVALID, "two-byte opcode is truncated")
        second_opcode = raw[cursor]
        cursor += 1
        if second_opcode == 0x1E:
            has_modrm = True
        else:
            _fail(RAW_BYTES_INVALID, "opcode is outside the closed two-byte encoding set")
    elif first_opcode in _MODRM_ONE_BYTE_OPCODES:
        has_modrm = True
    elif first_opcode in _NO_MODRM_ONE_BYTE_OPCODES:
        has_modrm = False
    else:
        _fail(RAW_BYTES_INVALID, "opcode is outside the closed one-byte encoding set")

    if not has_modrm:
        return False, False
    if cursor >= len(raw):
        _fail(RAW_BYTES_INVALID, "ModRM byte is missing")
    modrm = raw[cursor]
    has_sib = (modrm >> 6) != 0b11 and (modrm & 0x07) == 0b100
    return True, has_sib


def _has_destination_zero_extension(opcode: int, explicit: list[Any]) -> bool:
    """Return the exact bit-16 condition from the canonical destination operand."""

    if opcode == 2:
        destination = explicit[0]
    elif opcode in (3, 4):
        destination = explicit[0]
    else:
        return False
    return destination[0] == 0 and _reg_operand(destination, "destination", explicit=True)[2] == 32


def _validate_attributes(
    opcode: int,
    condition: int,
    explicit: list[Any],
    raw: bytes,
    attribute: int,
    instruction_offset: int,
    instruction_length: int,
) -> None:
    if attribute < 0 or attribute & ~_KNOWN_ATTRIBUTES:
        _fail(ATTRIBUTE_INVALID, "attribute mask contains an unknown bit")
    if not attribute & 1 and attribute & 0x1E:
        _fail(ATTRIBUTE_INVALID, "REX sub-bits are set without a REX prefix")
    if raw and 0x40 <= raw[0] <= 0x4F:
        rex = raw[0]
        expected = 1 | ((rex >> 3) & 1) << 1 | ((rex >> 2) & 1) << 2 | ((rex >> 1) & 1) << 3 | (rex & 1) << 4
        if attribute & 0x1F != expected:
            _fail(ATTRIBUTE_INVALID, "REX attributes do not match the raw prefix")
    elif attribute & 1:
        _fail(ATTRIBUTE_INVALID, "REX attribute is absent from raw bytes")
    immediate = [operand for operand in explicit if operand and operand[0] == 1]
    immediate_bits = 0
    if immediate:
        width = _immediate(immediate[0], "immediate")[0]
        immediate_bits = {8: 1 << 10, 16: 1 << 11, 32: 1 << 12, 64: 1 << 13}[width]
        extension = _immediate(immediate[0], "immediate")[3]
        immediate_bits |= {0: 0, 1: 1 << 14, 2: 1 << 15}[extension]
    if attribute & ((1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15)) != immediate_bits:
        _fail(ATTRIBUTE_INVALID, "immediate attributes do not match operands")
    addresses = [operand for operand in explicit if operand and operand[0] in (3, 4)]
    displacement_widths = []
    has_rip = False
    for operand in addresses:
        parts = _address_parts(
            operand,
            "address",
            memory=operand[0] == 3,
            instruction_offset=instruction_offset,
            instruction_length=instruction_length,
        )
        displacement_widths.append(parts[6])
        has_rip |= parts[3] == 17
    expected_disp = (1 << 8 if 8 in displacement_widths else 0) | (1 << 9 if 32 in displacement_widths else 0)
    if attribute & ((1 << 8) | (1 << 9)) != expected_disp:
        _fail(ATTRIBUTE_INVALID, "displacement attributes do not match operands")
    if bool(attribute & (1 << 17)) != has_rip:
        _fail(ATTRIBUTE_INVALID, "RIP-relative attribute does not match operands")
    if opcode == 1 and attribute != 1048672:
        _fail(ATTRIBUTE_INVALID, "ENDBR64 attribute mask is not exact")
    if opcode == 9 and attribute != 1048576:
        _fail(ATTRIBUTE_INVALID, "SYSCALL attribute mask is not exact")
    if opcode in (7, 8):
        branch = _branch(explicit[0], "branch")
        expected_branch = 1 << (18 if branch[0] == 8 else 19)
        if branch[0] == 32:
            expected_branch |= 1 << 20 if opcode == 7 else 0
        if attribute != expected_branch:
            _fail(ATTRIBUTE_INVALID, "branch attributes do not match the branch operand")
        if branch[0] == 8 and opcode == 7 and raw[0] & 0x0F != condition:
            _fail(RAW_BYTES_INVALID, "short branch opcode does not match its operand")
    if opcode not in (1, 7, 8, 9) and attribute & (1 << 20):
        _fail(ATTRIBUTE_INVALID, "0F opcode-map attribute is closed to this opcode")
    expected_modrm, expected_sib = _raw_modrm_and_sib(opcode, raw)
    if bool(attribute & (1 << 6)) != expected_modrm:
        _fail(ATTRIBUTE_INVALID, "ModRM attribute does not match the raw instruction")
    if bool(attribute & (1 << 7)) != expected_sib:
        _fail(ATTRIBUTE_INVALID, "SIB attribute does not match the raw instruction")
    if bool(attribute & (1 << 16)) != _has_destination_zero_extension(opcode, explicit):
        _fail(ATTRIBUTE_INVALID, "destination zero-extension attribute does not match operands")


def _validate_row(row: Any, page: bytes, owner: set[int]) -> tuple[int, int, int, list[Any]]:
    values = _array(row, "instruction row", 4)
    offset = _uint(values[0], "instruction offset", GATE_CODE_SIZE - 1)
    length = _uint(values[1], "instruction length", 15)
    if length == 0 or offset + length > GATE_CODE_SIZE:
        _fail(INSTRUCTION_INVALID, "instruction range is outside the gate code")
    if any(byte in owner for byte in range(offset, offset + length)):
        _fail(INSTRUCTION_INVALID, "instruction ranges overlap")
    detail = _array(values[3], "instruction detail", 9)
    opcode = _uint(values[2], "opcode", 10)
    if opcode == 0:
        _fail(INSTRUCTION_INVALID, "opcode zero is not defined")
    condition = _uint(detail[0], "condition", 15)
    explicit = _array(detail[1], "explicit operands")
    implicit_reads = _implicit_rows(
        detail[2],
        "implicit reads",
        allow_stack=opcode == 10,
        instruction_offset=offset,
        instruction_length=length,
    )
    implicit_writes = _array(detail[3], "implicit writes")
    for index, item in enumerate(implicit_writes):
        if item and item[0] == 0:
            reg, access, _width = _reg_operand(item, f"implicit writes[{index}]", explicit=False)
            if access not in (_ACCESS_WRITE, _ACCESS_CLOBBER):
                _fail(OPERAND_INVALID, "implicit write access is invalid")
            if reg == 17 and opcode not in (7, 8, 10):
                _fail(OPERAND_INVALID, "ordinary instruction has an implicit RIP write")
        elif item and item[0] == 3:
            parts = _address_parts(
                item,
                f"implicit writes[{index}]",
                memory=True,
                instruction_offset=offset,
                instruction_length=length,
            )
            if parts[0] != _ACCESS_WRITE:
                _fail(OPERAND_INVALID, "implicit write memory access is invalid")
        else:
            _fail(OPERAND_INVALID, "implicit writes contain an invalid operand")
    flags_read = _uint(detail[4], "flags read", _KNOWN_FLAGS)
    flags_write = _uint(detail[5], "flags write", _KNOWN_FLAGS)
    flags_undefined = _uint(detail[6], "flags undefined", _KNOWN_FLAGS)
    if flags_write & flags_undefined:
        _fail(INSTRUCTION_INVALID, "a flag cannot be both defined and undefined")
    attribute = _uint(detail[7], "attribute", _KNOWN_ATTRIBUTES)
    raw = _bytes(detail[8], "raw bytes", length)
    if page[offset : offset + length] != raw:
        _fail(RAW_BYTES_INVALID, "raw bytes do not equal the gate page slice")
    for index, operand in enumerate(explicit):
        _validate_operand(
            operand,
            f"explicit operands[{index}]",
            explicit=True,
            instruction_offset=offset,
            instruction_length=length,
        )
    if sum(1 for operand in explicit if operand and operand[0] == 1) > 1:
        _fail(OPERAND_INVALID, "an instruction contains more than one immediate")

    if opcode == 1:
        if condition != 0 or explicit or implicit_reads or implicit_writes or flags_read or flags_write or flags_undefined or raw != b"\xf3\x0f\x1e\xfa":
            _fail(INSTRUCTION_INVALID, "ENDBR64 contract mismatch")
    elif opcode == 2:
        if condition or len(explicit) != 2 or flags_read or flags_write or flags_undefined or implicit_reads:
            _fail(INSTRUCTION_INVALID, "MOV contract mismatch")
        left_tag, left_width = _validate_operand(explicit[0], "MOV destination", explicit=True, instruction_offset=offset, instruction_length=length)
        right_tag, right_width = _validate_operand(explicit[1], "MOV source", explicit=True, instruction_offset=offset, instruction_length=length)
        if left_tag not in (0, 3) or right_tag not in (0, 1, 3) or (left_tag == 3 and right_tag == 3) or left_width != right_width:
            _fail(OPERAND_INVALID, "MOV operand forms are closed")
        if left_tag == 0 and _reg_operand(explicit[0], "MOV destination", explicit=True)[1] != _ACCESS_WRITE:
            _fail(OPERAND_INVALID, "MOV register destination must be a write")
        if left_tag == 3 and _address_parts(explicit[0], "MOV destination", memory=True, instruction_offset=offset, instruction_length=length)[0] != _ACCESS_WRITE:
            _fail(OPERAND_INVALID, "MOV memory destination must be a write")
        if right_tag == 0 and _reg_operand(explicit[1], "MOV source", explicit=True)[1] != _ACCESS_READ:
            _fail(OPERAND_INVALID, "MOV register source must be a read")
        if right_tag == 3 and _address_parts(explicit[1], "MOV source", memory=True, instruction_offset=offset, instruction_length=length)[0] != _ACCESS_READ:
            _fail(OPERAND_INVALID, "MOV memory source must be a read")
        _expected_parent_writes(opcode, explicit, implicit_writes, attribute)
    elif opcode == 3:
        if condition or len(explicit) != 2 or flags_read or flags_write or flags_undefined or implicit_reads:
            _fail(INSTRUCTION_INVALID, "LEA contract mismatch")
        if explicit[0][0] != 0 or explicit[1][0] != 4:
            _fail(OPERAND_INVALID, "LEA operand forms are closed")
        if _reg_operand(explicit[0], "LEA destination", explicit=True)[1] != _ACCESS_WRITE:
            _fail(OPERAND_INVALID, "LEA destination must be a write")
        _expected_parent_writes(opcode, explicit, implicit_writes, attribute)
    elif opcode == 4:
        if condition or len(explicit) != 2 or flags_read or flags_write != 59 or flags_undefined != 4 or implicit_reads:
            _fail(INSTRUCTION_INVALID, "XOR_ZERO contract mismatch")
        first = _reg_operand(explicit[0], "XOR left", explicit=True)
        second = _reg_operand(explicit[1], "XOR right", explicit=True)
        if first[0] != second[0] or first[1] != _ACCESS_READ_WRITE or second[1] != _ACCESS_READ or first[2] not in (32, 64):
            _fail(OPERAND_INVALID, "XOR_ZERO operands are closed")
        _expected_parent_writes(opcode, explicit, implicit_writes, attribute)
    elif opcode in (5, 6):
        expected_write, expected_undefined = (59, 4) if opcode == 5 else (63, 0)
        if condition or len(explicit) != 2 or flags_read or flags_write != expected_write or flags_undefined != expected_undefined or implicit_reads or implicit_writes:
            _fail(INSTRUCTION_INVALID, "TEST/CMP contract mismatch")
        first_tag, first_width = _validate_operand(explicit[0], "comparison left", explicit=True, instruction_offset=offset, instruction_length=length)
        second_tag, second_width = _validate_operand(explicit[1], "comparison right", explicit=True, instruction_offset=offset, instruction_length=length)
        permitted_first = (0, 3)
        permitted_second = (0, 1) if opcode == 5 else (0, 1, 3)
        if first_tag not in permitted_first or second_tag not in permitted_second or (first_tag == 3 and second_tag == 3) or first_width != second_width:
            _fail(OPERAND_INVALID, "comparison operand forms are closed")
        for operand, label in ((explicit[0], "comparison left"), (explicit[1], "comparison right")):
            if operand[0] == 0 and _reg_operand(operand, label, explicit=True)[1] != _ACCESS_READ:
                _fail(OPERAND_INVALID, "comparison register operands must be reads")
            if operand[0] == 3 and _address_parts(operand, label, memory=True, instruction_offset=offset, instruction_length=length)[0] != _ACCESS_READ:
                _fail(OPERAND_INVALID, "comparison memory operands must be reads")
    elif opcode in (7, 8):
        if len(explicit) != 1 or explicit[0][0] != 2 or implicit_reads or implicit_writes != [[0, 17, 2]] or flags_write or flags_undefined:
            _fail(INSTRUCTION_INVALID, "branch contract mismatch")
        width, displacement, target, _ = _branch(explicit[0], "branch")
        if target != offset + length + displacement:
            _fail(OPERAND_INVALID, "branch target is not exact offset plus displacement")
        if opcode == 7:
            if condition not in _CONDITIONS or flags_read != _CONDITION_FLAGS[condition]:
                _fail(INSTRUCTION_INVALID, "conditional branch condition contract mismatch")
            if width == 8 and (len(raw) != 2 or raw[0] != 0x70 | condition or raw[1] != displacement & 0xFF):
                _fail(RAW_BYTES_INVALID, "short conditional branch raw bytes mismatch")
            if width == 32 and (len(raw) != 6 or raw[:2] != bytes((0x0F, 0x80 | condition)) or raw[2:] != displacement.to_bytes(4, "little", signed=True)):
                _fail(RAW_BYTES_INVALID, "near conditional branch raw bytes mismatch")
        else:
            if condition or flags_read:
                _fail(INSTRUCTION_INVALID, "unconditional branch has condition or flag reads")
            if width == 8 and (len(raw) != 2 or raw[0] != 0xEB or raw[1] != displacement & 0xFF):
                _fail(RAW_BYTES_INVALID, "short unconditional branch raw bytes mismatch")
            if width == 32 and (len(raw) != 5 or raw[0] != 0xE9 or raw[1:] != displacement.to_bytes(4, "little", signed=True)):
                _fail(RAW_BYTES_INVALID, "near unconditional branch raw bytes mismatch")
    elif opcode == 9:
        expected_reads = [[0, 1, 1], [0, 8, 1], [0, 7, 1], [0, 3, 1], [0, 11, 1], [0, 9, 1], [0, 10, 1]]
        expected_writes = [[0, 1, 2], [0, 2, 4], [0, 12, 4]]
        if condition or explicit or implicit_reads != expected_reads or implicit_writes != expected_writes or flags_read or flags_write or flags_undefined != 63 or raw != b"\x0f\x05":
            _fail(INSTRUCTION_INVALID, "SYSCALL contract mismatch")
    elif opcode == 10:
        expected_reads = [[0, 5, 1], [3, 1, 64, 64, 5, 0, 1, 0, 0, -1, 5, 0]]
        expected_writes = [[0, 5, 2], [0, 17, 2]]
        if condition or explicit or implicit_reads != expected_reads or implicit_writes != expected_writes or flags_read or flags_write or flags_undefined or attribute or raw != b"\xc3":
            _fail(INSTRUCTION_INVALID, "RET contract mismatch")
    _validate_attributes(opcode, condition, explicit, raw, attribute, offset, length)
    owner.update(range(offset, offset + length))
    return offset, length, opcode, detail


def _validate_cfg(instructions: dict[int, tuple[int, int, int, list[Any]]], cfg: list[Any]) -> None:
    if not instructions or 0 not in instructions:
        _fail(CFG_INVALID, "instruction graph must begin at offset zero")
    all_offsets = set(instructions)
    successors: dict[int, list[int]] = {}
    for offset, (row_offset, length, opcode, detail) in instructions.items():
        explicit = detail[1]
        fallthrough = offset + length
        if opcode == 7:
            target = _branch(explicit[0], "branch")[2]
            if fallthrough >= GATE_CODE_SIZE or target == fallthrough:
                _fail(CFG_INVALID, "conditional branch successors are invalid")
            successors[offset] = [target, fallthrough]
        elif opcode == 8:
            successors[offset] = [_branch(explicit[0], "branch")[2]]
        elif opcode == 10:
            successors[offset] = []
        else:
            if fallthrough >= GATE_CODE_SIZE:
                _fail(CFG_INVALID, "nonterminal instruction lacks a fallthrough")
            successors[offset] = [fallthrough]
        if any(target not in all_offsets for target in successors[offset]):
            _fail(CFG_INVALID, "successor does not identify an instruction boundary")
    reachable = {0}
    pending = [0]
    while pending:
        current = pending.pop()
        for successor in successors[current]:
            if successor not in reachable:
                reachable.add(successor)
                pending.append(successor)
    if reachable != all_offsets:
        _fail(CFG_INVALID, "instruction graph contains unreachable rows")
    owner = set()
    for offset, (_row_offset, length, _opcode, _detail) in instructions.items():
        owner.update(range(offset, offset + length))
    if owner != set(range(GATE_CODE_SIZE)):
        _fail(CFG_INVALID, "instruction graph does not cover the complete gate code")
    block_starts = {0}
    for offset, (_row_offset, _length, opcode, detail) in instructions.items():
        if opcode in (7, 8):
            block_starts.add(_branch(detail[1][0], "branch")[2])
        if opcode in (7, 9):
            fallthrough = offset + instructions[offset][1]
            if fallthrough < GATE_CODE_SIZE:
                block_starts.add(fallthrough)
    if not block_starts <= all_offsets:
        _fail(CFG_INVALID, "block start is not an instruction boundary")
    blocks: dict[int, tuple[int, list[int]]] = {}
    assigned: set[int] = set()
    for start in sorted(block_starts):
        if start in assigned:
            _fail(CFG_INVALID, "block-start set overlaps an existing block")
        current = start
        members: list[int] = []
        while True:
            if current in assigned or current not in instructions:
                _fail(CFG_INVALID, "block construction encountered an invalid instruction")
            assigned.add(current)
            members.append(current)
            opcode = instructions[current][2]
            if opcode in (7, 8, 9, 10):
                break
            next_offset = current + instructions[current][1]
            if next_offset >= GATE_CODE_SIZE:
                _fail(CFG_INVALID, "nonterminal block has no next instruction")
            if next_offset in block_starts:
                break
            current = next_offset
        last = members[-1]
        opcode = instructions[last][2]
        if opcode == 7:
            terminal = 1
            row_successors = successors[last]
        elif opcode == 8:
            terminal = 2
            row_successors = successors[last]
        elif opcode == 10:
            terminal = 3
            row_successors = []
        elif opcode == 9:
            terminal = 4
            row_successors = successors[last]
        else:
            terminal = 0
            row_successors = [last + instructions[last][1]]
        if any(value not in block_starts for value in row_successors):
            _fail(CFG_INVALID, "CFG successor is not a basic-block start")
        blocks[start] = (terminal, row_successors)
    if assigned != all_offsets:
        _fail(CFG_INVALID, "not every instruction belongs to one basic block")
    if len(cfg) != len(blocks):
        _fail(CFG_INVALID, "CFG row count does not match constructed blocks")
    previous = -1
    for index, row in enumerate(cfg):
        values = _array(row, f"CFG row {index}", 3)
        start = _uint(values[0], f"CFG row {index}.start", GATE_CODE_SIZE - 1)
        terminal = _uint(values[1], f"CFG row {index}.terminal", 4)
        row_successors = _array(values[2], f"CFG row {index}.successors")
        if start <= previous or start not in blocks:
            _fail(CFG_INVALID, "CFG rows are not strictly ordered block rows")
        expected_terminal, expected_successors = blocks[start]
        if terminal != expected_terminal or row_successors != expected_successors:
            _fail(CFG_INVALID, "CFG row differs from the closed block construction")
        if len(row_successors) != len(set(row_successors)):
            _fail(CFG_INVALID, "CFG row contains a duplicate successor")
        previous = start


def validate_launch_gate_decoder_manifest_v1(
    gate_page: bytes,
    decoder_output: bytes,
) -> LaunchGateDecoderManifestValidationResult:
    """Validate one completed decoder output without normalizing it."""

    try:
        if type(gate_page) is not bytes or len(gate_page) != GATE_PAGE_SIZE:
            _fail(PAGE_INVALID, "gate page must be exactly 4096 bytes")
        if sha256(gate_page).digest() != GATE_PAGE_SHA256:
            _fail(PAGE_HASH_MISMATCH, "gate page does not match the pinned page hash")
        if type(decoder_output) is not bytes:
            _fail(OUTPUT_INPUT_INVALID, "decoder output must be bytes")
        wrapper = decode_canonical_cbor_v1(decoder_output)
        fields = _array(wrapper, "decoder wrapper", 6)
        if fields[0] != PROTOCOL_ID or fields[1] != WIRE_VERSION:
            _fail(WRAPPER_INVALID, "wrapper protocol or wire version is not exact")
        if _bytes(fields[2], "wrapper page hash", 32) != GATE_PAGE_SHA256:
            _fail(WRAPPER_INVALID, "wrapper page hash is not the pinned raw digest")
        if fields[3] != GATE_CODE_SIZE:
            _fail(WRAPPER_INVALID, "wrapper gate code size is not 874")
        instruction_manifest = _array(fields[4], "instruction manifest")
        cfg_manifest = _array(fields[5], "CFG manifest")
        previous = -1
        owner: set[int] = set()
        instructions: dict[int, tuple[int, int, int, list[Any]]] = {}
        for index, row in enumerate(instruction_manifest):
            offset = _uint(_array(row, f"instruction row {index}", 4)[0], "instruction offset", GATE_CODE_SIZE - 1)
            if offset <= previous:
                _fail(INSTRUCTION_INVALID, "instruction rows are not strictly ordered")
            checked = _validate_row(row, gate_page, owner)
            instructions[offset] = checked
            previous = offset
        if owner != set(range(GATE_CODE_SIZE)):
            _fail(INSTRUCTION_INVALID, "instruction rows do not cover [0,874)")
        _validate_cfg(instructions, cfg_manifest)
        instruction_bytes = encode_canonical_cbor_v1(instruction_manifest)
        cfg_bytes = encode_canonical_cbor_v1(cfg_manifest)
        wrapper_bytes = encode_canonical_cbor_v1(fields)
        if wrapper_bytes != decoder_output:
            _fail(CBOR_NONCANONICAL, "independent wrapper re-encoding differs from output bytes")
        return LaunchGateDecoderManifestValidationResult(
            valid=True,
            issues=(),
            wrapper_bytes=wrapper_bytes,
            instruction_manifest_bytes=instruction_bytes,
            cfg_manifest_bytes=cfg_bytes,
            instruction_manifest_sha256=sha256(instruction_bytes).digest(),
            cfg_manifest_sha256=sha256(cfg_bytes).digest(),
            wrapper_sha256=sha256(wrapper_bytes).digest(),
        )
    except LaunchGateDecoderManifestError as exc:
        return LaunchGateDecoderManifestValidationResult(
            valid=False,
            issues=(LaunchGateDecoderManifestIssue(exc.code, str(exc)),),
        )


def compare_launch_gate_decoder_outputs_v1(
    gate_page: bytes,
    first_output: bytes,
    second_output: bytes,
) -> LaunchGateDecoderAgreementResult:
    """Validate two outputs and require exact file-byte agreement first."""

    if type(first_output) is not bytes or type(second_output) is not bytes:
        issue = LaunchGateDecoderManifestIssue(OUTPUT_INPUT_INVALID, "both decoder outputs must be bytes")
        return LaunchGateDecoderAgreementResult(False, (issue,))
    if first_output != second_output:
        issue = LaunchGateDecoderManifestIssue(
            OUTPUT_BYTE_MISMATCH,
            "decoder outputs differ byte-for-byte; no normalization was applied",
        )
        return LaunchGateDecoderAgreementResult(False, (issue,))
    first = validate_launch_gate_decoder_manifest_v1(gate_page, first_output)
    second = validate_launch_gate_decoder_manifest_v1(gate_page, second_output)
    if not first.valid:
        return LaunchGateDecoderAgreementResult(False, first.issues, first=first, second=second)
    if not second.valid:
        return LaunchGateDecoderAgreementResult(False, second.issues, first=first, second=second)
    return LaunchGateDecoderAgreementResult(True, (), first=first, second=second)


# Explicit aliases make the boundary easy to discover without adding a second
# implementation or an authority-bearing convenience layer.
strict_decode_canonical_cbor_v1 = decode_canonical_cbor_v1
strict_encode_canonical_cbor_v1 = encode_canonical_cbor_v1
validate_decoder_output_v1 = validate_launch_gate_decoder_manifest_v1
compare_decoder_outputs_v1 = compare_launch_gate_decoder_outputs_v1


__all__ = [
    "AUTHORITY",
    "AGENT_MODIFICATION_AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "GATE_CODE_SIZE",
    "GATE_PAGE_SHA256",
    "GATE_PAGE_SIZE",
    "LaunchGateDecoderAgreementResult",
    "LaunchGateDecoderManifestError",
    "LaunchGateDecoderManifestIssue",
    "LaunchGateDecoderManifestValidationResult",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "SEALED_HOLDOUT_ACCESS_AUTHORITY",
    "WIRE_VERSION",
    "ZERO_AUTHORITY",
    "compare_decoder_outputs_v1",
    "compare_launch_gate_decoder_outputs_v1",
    "decode_canonical_cbor_v1",
    "encode_canonical_cbor_v1",
    "strict_decode_canonical_cbor_v1",
    "strict_encode_canonical_cbor_v1",
    "validate_decoder_output_v1",
    "validate_launch_gate_decoder_manifest_v1",
]
