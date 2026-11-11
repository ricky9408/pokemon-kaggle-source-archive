"""Independent offline reference for the frozen Stage-1 custody receipt V2.

This module is deliberately separate from the repository's receipt consumer and
canonical trace codec.  It implements only the arrays/uint/byte-string CBOR
profile needed to construct and inspect the 31-field V2 wire value.  The
vectors use an all-zero image identity, so they are syntactically useful but
deliberately non-evidentiary.

No function in this module writes receipt bytes.  The command-line self-test
prints only lengths and SHA-256 summaries.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple


PROTOCOL_ID = 631302
WIRE_VERSION = 2
BODY_FIELD_COUNT = 31
SHA256_SIZE = 32
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
DOMAIN_PREFIX = b"V631302_STAGE1_EXTRACTION_CUSTODY_RECEIPT_V2\x00"
ZERO_IMAGE_ID = b"\x00" * SHA256_SIZE

S_IFREG = 0o100000
S_IFDIR = 0o040000
OVERLAYFS_SUPER_MAGIC = 0x794C7630
SECCOMP_SYSCALLS = (
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


class ReferenceError(ValueError):
    """Raised when a value is outside the frozen structural wire profile."""


def _fail(message: str) -> None:
    raise ReferenceError(message)


def _head(major: int, value: int) -> bytes:
    if type(value) is not int or value < 0 or value > UINT64_MAX:
        _fail("CBOR argument is not an unsigned uint64")
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 0xFF:
        return bytes(((major << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")


def _uint(value: object, label: str, maximum: int = UINT64_MAX) -> bytes:
    if type(value) is not int or value < 0 or value > maximum:
        _fail(f"{label} must be an unsigned integer <= {maximum}")
    return _head(0, value)


def _bytes(value: object, label: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        _fail(f"{label} must be a byte string")
    if length is not None and len(value) != length:
        _fail(f"{label} must contain exactly {length} bytes")
    return _head(2, len(value)) + value


def _sequence(value: object, label: str) -> list[object] | tuple[object, ...]:
    if type(value) is not list and type(value) is not tuple:
        _fail(f"{label} must be a list or tuple")
    return value


def _array(parts: list[bytes] | tuple[bytes, ...]) -> bytes:
    return _head(4, len(parts)) + b"".join(parts)


def _fixed_array(value: object, count: int, label: str, item_encoder: Any) -> bytes:
    values = _sequence(value, label)
    if len(values) != count:
        _fail(f"{label} must contain exactly {count} elements")
    return _array(tuple(item_encoder(item, f"{label}[{index}]") for index, item in enumerate(values)))


def encode_namespace_identity(value: object) -> bytes:
    return _fixed_array(value, 3, "namespace_identity", lambda item, label: _uint(item, label))


def encode_object_identity(value: object) -> bytes:
    values = _sequence(value, "object_identity")
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
    if len(values) != len(maxima):
        _fail("object_identity must contain exactly 9 elements")
    return _array(tuple(_uint(item, f"object_identity[{index}]", maxima[index]) for index, item in enumerate(values)))


def encode_file_identity(value: object) -> bytes:
    values = _sequence(value, "file_identity")
    if len(values) != 2:
        _fail("file_identity must contain exactly 2 elements")
    return _array((encode_object_identity(values[0]), _bytes(values[1], "file_identity[1]", SHA256_SIZE)))


def encode_directory_identity(value: object) -> bytes:
    values = _sequence(value, "directory_identity")
    if len(values) != 5:
        _fail("directory_identity must contain exactly 5 elements")
    return _array(
        (
            encode_object_identity(values[0]),
            _uint(values[1], "directory_identity[1]"),
            _uint(values[2], "directory_identity[2]", UINT32_MAX),
            _uint(values[3], "directory_identity[3]", UINT32_MAX),
            _uint(values[4], "directory_identity[4]"),
        )
    )


def encode_mount_info(value: object) -> bytes:
    values = _sequence(value, "mount_info")
    if len(values) != 17:
        _fail("mount_info must contain exactly 17 elements")
    byte_array = lambda item, label: _bytes(item, label)
    return _array(
        (
            _uint(values[0], "mount_info[0]"),
            _uint(values[1], "mount_info[1]"),
            _uint(values[2], "mount_info[2]"),
            _uint(values[3], "mount_info[3]", UINT32_MAX),
            _uint(values[4], "mount_info[4]", UINT32_MAX),
            _bytes(values[5], "mount_info[5]"),
            _bytes(values[6], "mount_info[6]"),
            _fixed_array(values[7], len(_sequence(values[7], "mount_info[7]")), "mount_info[7]", byte_array),
            _fixed_array(values[8], len(_sequence(values[8], "mount_info[8]")), "mount_info[8]", byte_array),
            _bytes(values[9], "mount_info[9]"),
            _bytes(values[10], "mount_info[10]"),
            _fixed_array(values[11], len(_sequence(values[11], "mount_info[11]")), "mount_info[11]", byte_array),
            _uint(values[12], "mount_info[12]"),
            _uint(values[13], "mount_info[13]", UINT32_MAX),
            _uint(values[14], "mount_info[14]", UINT32_MAX),
            _uint(values[15], "mount_info[15]"),
            _bytes(values[16], "mount_info[16]"),
        )
    )


def encode_root_mount_custody(value: object) -> bytes:
    values = _sequence(value, "root_mount_custody")
    if len(values) != 2:
        _fail("root_mount_custody must contain exactly 2 elements")
    return _array((encode_mount_info(values[0]), encode_object_identity(values[1])))


def encode_cwd_identity(value: object) -> bytes:
    return _fixed_array(value, 4, "cwd_identity", lambda item, label: _uint(item, label))


def encode_census(value: object) -> bytes:
    rows = _sequence(value, "census")
    encoded_rows = []
    for row_index, row in enumerate(rows):
        fields = _sequence(row, f"census[{row_index}]")
        if len(fields) != 3:
            _fail(f"census[{row_index}] must contain exactly 3 elements")
        tasks = _sequence(fields[2], f"census[{row_index}][2]")
        encoded_tasks = []
        for task_index, task in enumerate(tasks):
            task_fields = _sequence(task, f"census[{row_index}][2][{task_index}]")
            if len(task_fields) != 2:
                _fail(f"census[{row_index}][2][{task_index}] must contain exactly 2 elements")
            encoded_tasks.append(
                _array((_uint(task_fields[0], "task tid"), encode_cwd_identity(task_fields[1])))
            )
        encoded_rows.append(
            _array(
                (
                    _uint(fields[0], "census pid"),
                    _uint(fields[1], "census starttime"),
                    _array(tuple(encoded_tasks)),
                )
            )
        )
    return _array(tuple(encoded_rows))


def encode_blob_digest(value: object) -> bytes:
    values = _sequence(value, "blob_digest")
    if len(values) != 2:
        _fail("blob_digest must contain exactly 2 elements")
    return _array((_uint(values[0], "blob_digest[0]"), _bytes(values[1], "blob_digest[1]", SHA256_SIZE)))


def encode_seccomp_policy(value: object) -> bytes:
    values = _sequence(value, "seccomp_policy")
    if len(values) != 6:
        _fail("seccomp_policy must contain exactly 6 elements")
    syscalls = _sequence(values[4], "seccomp_policy[4]")
    return _array(
        (
            _uint(values[0], "seccomp_policy[0]"),
            _uint(values[1], "seccomp_policy[1]"),
            _uint(values[2], "seccomp_policy[2]"),
            _uint(values[3], "seccomp_policy[3]"),
            _array(tuple(_uint(item, "seccomp syscall") for item in syscalls)),
            _bytes(values[5], "seccomp_policy[5]", SHA256_SIZE),
        )
    )


def encode_build_principal(value: object) -> bytes:
    return _fixed_array(
        value,
        2,
        "build_principal",
        lambda item, label: _uint(item, label, UINT32_MAX),
    )


def encode_byte_array(value: object, label: str = "byte_array") -> bytes:
    values = _sequence(value, label)
    return _array(tuple(_bytes(item, f"{label}[{index}]") for index, item in enumerate(values)))


def encode_final_directory_listing(value: object) -> bytes:
    rows = _sequence(value, "final_directory_listing")
    if len(rows) != 2:
        _fail("final_directory_listing must contain exactly 2 elements")
    encoded = []
    for index, row in enumerate(rows):
        fields = _sequence(row, f"final_directory_listing[{index}]")
        if len(fields) != 2:
            _fail(f"final_directory_listing[{index}] must contain exactly 2 elements")
        encoded.append(_array((_bytes(fields[0], "listing name"), encode_file_identity(fields[1]))))
    return _array(tuple(encoded))


def encode_body(body: object) -> bytes:
    """Encode one typed-ish 31-field V2 body exactly once.

    This is a structural encoder, not a custody-semantic validator.  It
    intentionally accepts inconsistent duplicate/cross-reference fields so a
    caller can test that a later semantic consumer rejects them.
    """

    fields = _sequence(body, "Stage1ExtractionCustodyBodyV2")
    if len(fields) != BODY_FIELD_COUNT:
        _fail("Stage1ExtractionCustodyBodyV2 must contain exactly 31 elements")
    if type(fields[0]) is not bytes or fields[0] != ZERO_IMAGE_ID:
        _fail("body[0] must be exactly 32 zero bytes for offline vectors")
    encoded = (
        _bytes(fields[0], "body[0]", SHA256_SIZE),
        encode_file_identity(fields[1]),
        encode_namespace_identity(fields[2]),
        encode_namespace_identity(fields[3]),
        encode_root_mount_custody(fields[4]),
        encode_mount_info(fields[5]),
        encode_directory_identity(fields[6]),
        encode_file_identity(fields[7]),
        encode_file_identity(fields[8]),
        encode_file_identity(fields[9]),
        encode_byte_array(fields[10], "body[10]"),
        encode_byte_array(fields[11], "body[11]"),
        encode_seccomp_policy(fields[12]),
        encode_census(fields[13]),
        encode_census(fields[14]),
        _uint(fields[15], "body[15]"),
        _uint(fields[16], "body[16]"),
        _fixed_array(fields[17], 2, "body[17]", lambda item, label: _uint(item, label)),
        encode_census(fields[18]),
        encode_census(fields[19]),
        _fixed_array(fields[20], 2, "body[20]", lambda item, label: _uint(item, label)),
        encode_root_mount_custody(fields[21]),
        encode_mount_info(fields[22]),
        encode_directory_identity(fields[23]),
        encode_file_identity(fields[24]),
        encode_file_identity(fields[25]),
        encode_final_directory_listing(fields[26]),
        encode_blob_digest(fields[27]),
        encode_blob_digest(fields[28]),
        _fixed_array(fields[29], 2, "body[29]", lambda item, label: encode_census(item)),
        encode_build_principal(fields[30]),
    )
    return _array(encoded)


def compute_root(body_bytes: bytes) -> bytes:
    """Compute the V2 root from already encoded body bytes."""

    if type(body_bytes) is not bytes:
        _fail("body_bytes must be bytes")
    return hashlib.sha256(DOMAIN_PREFIX + body_bytes).digest()


def recompute_root(body: object) -> bytes:
    """Encode a typed body once and compute its V2 root."""

    return compute_root(encode_body(body))


def encode_wrapper(body: object) -> bytes:
    """Construct the wrapper using the one body byte string used for the root."""

    body_bytes = encode_body(body)
    root = compute_root(body_bytes)
    return _array(
        (
            _uint(PROTOCOL_ID, "wrapper protocol"),
            _uint(WIRE_VERSION, "wrapper version"),
            body_bytes,
            _bytes(root, "wrapper root", SHA256_SIZE),
        )
    )


class _Node(NamedTuple):
    value: object
    start: int
    end: int
    children: tuple["_Node", ...] = ()


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0

    def _take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.raw):
            _fail("truncated CBOR value")
        result = self.raw[self.offset : self.offset + count]
        self.offset += count
        return result

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            _fail("indefinite or unsupported CBOR argument")
        value = int.from_bytes(self._take(width), "big")
        minimum = {1: 24, 2: 256, 4: 65536, 8: 1 << 32}[width]
        if value < minimum:
            _fail("CBOR argument is not minimally encoded")
        return value

    def value(self, depth: int = 0) -> _Node:
        if depth > 128:
            _fail("CBOR nesting exceeds reference bound")
        start = self.offset
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F
        if major == 0:
            value = self._argument(additional)
            return _Node(value, start, self.offset)
        if major == 2:
            length = self._argument(additional)
            payload = self._take(length)
            return _Node(payload, start, self.offset)
        if major != 4:
            _fail("reference accepts only arrays, unsigned integers, and byte strings")
        length = self._argument(additional)
        children = tuple(self.value(depth + 1) for _ in range(length))
        return _Node(tuple(child.value for child in children), start, self.offset, children)


class WrapperView(NamedTuple):
    protocol: int
    version: int
    body: tuple[object, ...]
    body_bytes: bytes
    root: bytes
    wrapper_bytes: bytes


def parse_strict_wrapper(raw: bytes) -> WrapperView:
    """Parse, structurally verify, and expose the exact raw body element."""

    if type(raw) is not bytes or not raw:
        _fail("wrapper must be nonempty bytes")
    reader = _Reader(raw)
    wrapper_node = reader.value()
    if reader.offset != len(raw):
        _fail("trailing bytes after wrapper")
    if len(wrapper_node.children) != 4:
        _fail("wrapper must contain exactly 4 elements")
    wrapper = wrapper_node.value
    if type(wrapper) is not tuple or wrapper[0] != PROTOCOL_ID or wrapper[1] != WIRE_VERSION:
        _fail("wrapper protocol or version is not exact")
    body_node = wrapper_node.children[2]
    if type(body_node.value) is not tuple or len(body_node.value) != BODY_FIELD_COUNT:
        _fail("wrapper body must contain exactly 31 elements")
    body = body_node.value
    if body[0] != ZERO_IMAGE_ID:
        _fail("offline wrapper body image identity must be 32 zero bytes")
    body_bytes = raw[body_node.start : body_node.end]
    if encode_body(body) != body_bytes:
        _fail("body is not the exact canonical V2 structural encoding")
    supplied_root = wrapper[3]
    if type(supplied_root) is not bytes or len(supplied_root) != SHA256_SIZE:
        _fail("wrapper root must be a 32-byte byte string")
    expected_root = compute_root(body_bytes)
    if supplied_root != expected_root:
        _fail("wrapper root does not match the exact body bytes")
    return WrapperView(PROTOCOL_ID, WIRE_VERSION, body, body_bytes, supplied_root, raw)


def verify_wrapper(raw: bytes) -> WrapperView:
    """Alias with an explicit verification-oriented name."""

    return parse_strict_wrapper(raw)


def extract_body_bytes(raw: bytes) -> bytes:
    """Return the exact third wrapper element after strict verification."""

    return parse_strict_wrapper(raw).body_bytes


def _digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _text_for_mutation(value: bytes) -> bytes:
    """Encode one test-only CBOR text item without accepting it in the profile."""

    return _head(3, len(value)) + value


def _generic_array_profile_encode(value: object) -> bytes:
    """Encode arrays/uint/bytes for malformed structural test construction.

    Production reference encoding remains the typed 31-field path above. This
    helper exists only to build deliberately reordered or wrong-sized bodies.
    """

    if type(value) is int:
        return _uint(value, "mutation integer")
    if type(value) is bytes:
        return _bytes(value, "mutation bytes")
    if type(value) is list or type(value) is tuple:
        return _array(tuple(_generic_array_profile_encode(item) for item in value))
    _fail("mutation helper accepts only arrays, unsigned integers, and bytes")


def _wrapper_from_encoded_body(
    encoded_body: bytes,
    root: bytes,
    *,
    protocol: int = PROTOCOL_ID,
    version: int = WIRE_VERSION,
) -> bytes:
    return _array(
        (
            _uint(protocol, "mutation protocol"),
            _uint(version, "mutation version"),
            encoded_body,
            _bytes(root, "mutation root", SHA256_SIZE),
        )
    )


def _object(seed: int, mode: int) -> list[int]:
    return [
        seed,
        seed + 1,
        seed + 2,
        1000 + seed,
        mode,
        2000 + seed,
        3000 + seed,
        4000 + seed,
        5000 + seed,
    ]


def _file(seed: int, digest: bytes, mode: int = S_IFREG | 0o444) -> list[object]:
    return [_object(seed, mode), digest]


def _mount(seed: int) -> list[object]:
    return [
        1,
        10 + seed,
        20 + seed,
        30 + seed,
        40 + seed,
        f"/root-{seed}".encode("ascii"),
        f"/point-{seed}".encode("ascii"),
        [f"mount-option-{seed}".encode("ascii")],
        [f"optional-{seed}".encode("ascii")],
        f"filesystem-{seed}".encode("ascii"),
        f"source-{seed}".encode("ascii"),
        [f"super-option-{seed}".encode("ascii")],
        OVERLAYFS_SUPER_MAGIC,
        50 + seed,
        60 + seed,
        70 + seed,
        f"raw-mountinfo-{seed}".encode("ascii"),
    ]


def _census(seed: int) -> list[object]:
    return [
        [1, 100 + seed, [[1, [1, 8, 0, 100]]]],
        [2, 200 + seed, [[2, [2, 8, 0, 200]]]],
    ]


def _base_body(tag: str) -> list[object]:
    def h(index: int) -> bytes:
        return _digest((tag + ":" + str(index)).encode("ascii"))

    root_mount = [_mount(ord(tag)), _object(500 + ord(tag), S_IFDIR | 0o755)]
    extraction_dir = [_object(600 + ord(tag), S_IFDIR | 0o700), OVERLAYFS_SUPER_MAGIC, 1, 2, 0]
    raw = _file(700 + ord(tag), h(7))
    page = _file(701 + ord(tag), h(25))
    return [
        ZERO_IMAGE_ID,
        _file(100 + ord(tag), h(1), S_IFREG | 0o755),
        [1, 2, 3],
        [4, 5, 6],
        root_mount,
        _mount(ord(tag) + 1),
        extraction_dir,
        raw,
        _file(102 + ord(tag), h(8), S_IFREG | 0o755),
        _file(103 + ord(tag), h(9), S_IFREG | 0o755),
        [b"/usr/bin/env", b"-i", (tag + "-argv").encode("ascii")],
        [b"PATH=/usr/bin:/bin", (tag + "-env").encode("ascii")],
        [0xC000003E, 0x40000000, 0x80000000, 0x7FFF0000, list(SECCOMP_SYSCALLS), h(12)],
        _census(1),
        _census(1),
        2,
        900 + ord(tag),
        [1, 2],
        _census(2),
        _census(2),
        [1, 0],
        root_mount,
        _mount(ord(tag) + 1),
        extraction_dir,
        raw,
        page,
        [[b"LaunchGateV1.o", raw], [b"LaunchGateV1.page", page]],
        [0, h(27)],
        [0, h(28)],
        [_census(3), _census(3)],
        [1000, 1000],
    ]


def vector_a() -> dict[str, object]:
    """Field-order sentinel vector; every top-level field remains distinct."""

    body = _base_body("A")
    body[14] = _census(11)
    body[19] = _census(22)
    body[29][1] = _census(33)
    body[30] = [1000, 1001]
    return {"body": body, "semantic_rejection_expected": True, "reason": "zero image identity"}


def vector_b() -> dict[str, object]:
    """Unsigned-CBOR boundary vector spanning minimal-header transitions."""

    body = _base_body("B")
    body[15] = 0
    body[16] = 23
    body[17] = [24, 255]
    body[20] = [256, 65535]
    body[30] = [65536, UINT32_MAX]
    body[2] = [UINT64_MAX, 0, 1]
    body[3] = [UINT32_MAX, UINT32_MAX + 1, 2]
    body[4][1][0] = UINT64_MAX
    return {"body": body, "semantic_rejection_expected": True, "reason": "zero image identity"}


def vector_c() -> dict[str, object]:
    """Byte-string and array-length boundary vector."""

    body = _base_body("C")
    body[10] = [b"", b"x" * 23, b"y" * 24, b"z" * 255, b"q" * 256]
    body[11] = [b"", b"e" * 23, b"f" * 24]
    body[13] = [
        [
            1,
            101,
            [
                [1, [1, 8, 0, 100]],
                [3, [3, 9, 1, 101]],
            ],
        ],
        [2, 202, [[2, [2, 8, 0, 200]]]],
        [4, 404, [[4, [4, 10, 2, 400]]]],
    ]
    body[27] = [0, b"\x00" * 32]
    body[28] = [256, _digest(b"C-stdout")]
    return {"body": body, "semantic_rejection_expected": True, "reason": "zero image identity"}


def vector_d() -> dict[str, object]:
    """Inconsistent duplicate/cross-reference vector for semantic rejection."""

    body = _base_body("D")
    post_root = [list(body[21][0]), list(body[21][1])]
    post_root[1][3] += 1
    body[21] = post_root
    listing_raw = [list(body[24][0]), bytes(body[24][1])]
    listing_raw[0][3] += 10
    listing_raw[1] = _digest(b"D-listing-raw")
    listing_page = [list(body[25][0]), bytes(body[25][1])]
    listing_page[0][3] += 20
    listing_page[1] = _digest(b"D-listing-page")
    body[26] = [
        [b"LaunchGateV1.o", listing_raw],
        [b"LaunchGateV1.page", listing_page],
    ]
    body[30] = [1234, 1235]
    body[29][1] = []
    return {
        "body": body,
        "semantic_rejection_expected": True,
        "reason": (
            "zero image identity plus root/census/build-principal and "
            "top-level/listing identity mismatches"
        ),
    }


def generate_vectors() -> dict[str, dict[str, object]]:
    """Return deterministic A-D bodies and summaries without emitting full bytes."""

    vectors = {"A": vector_a(), "B": vector_b(), "C": vector_c(), "D": vector_d()}
    for name, vector in vectors.items():
        body_bytes = encode_body(vector["body"])
        wrapper_bytes = encode_wrapper(vector["body"])
        parsed = verify_wrapper(wrapper_bytes)
        vector["body_bytes"] = body_bytes
        vector["wrapper_bytes"] = wrapper_bytes
        vector["body_sha256"] = hashlib.sha256(body_bytes).hexdigest()
        vector["wrapper_sha256"] = hashlib.sha256(wrapper_bytes).hexdigest()
        vector["root"] = parsed.root
        vector["name"] = name
    return vectors


make_vectors = generate_vectors


def _self_test() -> None:
    vectors = generate_vectors()
    if tuple(vectors) != ("A", "B", "C", "D"):
        _fail("vector ordering is not deterministic")
    for name, vector in vectors.items():
        body = vector["body"]
        if body[0] != ZERO_IMAGE_ID:
            _fail(f"vector {name} does not have a zero image identity")
        parsed = verify_wrapper(vector["wrapper_bytes"])
        if parsed.body_bytes != vector["body_bytes"]:
            _fail(f"vector {name} body slice changed")
        if recompute_root(body) != parsed.root:
            _fail(f"vector {name} root mismatch")
        if extract_body_bytes(vector["wrapper_bytes"]) != vector["body_bytes"]:
            _fail(f"vector {name} raw body extraction mismatch")
        if not vector["semantic_rejection_expected"]:
            _fail(f"vector {name} is missing its non-evidentiary marker")
    malformed = bytearray(vectors["A"]["wrapper_bytes"])
    malformed[-1] ^= 1
    try:
        verify_wrapper(bytes(malformed))
    except ReferenceError:
        pass
    else:
        _fail("root mutation was accepted")

    def expect_rejection(raw: bytes, label: str) -> None:
        try:
            verify_wrapper(raw)
        except ReferenceError:
            return
        _fail(f"malformed wrapper was accepted: {label}")

    a_body = vectors["A"]["body"]
    a_body_bytes = vectors["A"]["body_bytes"]
    a_root = vectors["A"]["root"]
    a_wrapper = vectors["A"]["wrapper_bytes"]

    def require_adjacent_swap_changes(
        swapped_body: list[object], label: str
    ) -> None:
        swapped_body_bytes = encode_body(swapped_body)
        swapped_wrapper = encode_wrapper(swapped_body)
        swapped_root = recompute_root(swapped_body)
        if swapped_body_bytes == a_body_bytes:
            _fail(f"{label} did not change body bytes")
        if hashlib.sha256(swapped_body_bytes).digest() == hashlib.sha256(
            a_body_bytes
        ).digest():
            _fail(f"{label} did not change body SHA-256")
        if swapped_root == a_root:
            _fail(f"{label} did not change V2 root")
        if swapped_wrapper == a_wrapper:
            _fail(f"{label} did not change wrapper bytes")
        if hashlib.sha256(swapped_wrapper).digest() == hashlib.sha256(
            a_wrapper
        ).digest():
            _fail(f"{label} did not change wrapper SHA-256")

    for left, right in ((13, 14), (18, 19)):
        swapped = list(a_body)
        swapped[left], swapped[right] = swapped[right], swapped[left]
        require_adjacent_swap_changes(swapped, f"Vector A positions {left}/{right}")
    swapped = list(a_body)
    swapped_post = list(a_body[29])
    swapped_post[0], swapped_post[1] = swapped_post[1], swapped_post[0]
    swapped[29] = swapped_post
    require_adjacent_swap_changes(swapped, "Vector A position 29 censuses")

    body30 = _generic_array_profile_encode(a_body[:-1])
    body32 = _generic_array_profile_encode([*a_body, 0])
    expect_rejection(
        _wrapper_from_encoded_body(body30, compute_root(body30)), "30-field body"
    )
    expect_rejection(
        _wrapper_from_encoded_body(body32, compute_root(body32)), "32-field body"
    )
    expect_rejection(
        _array(
            (
                _uint(PROTOCOL_ID, "protocol"),
                _uint(WIRE_VERSION, "version"),
                a_body_bytes,
            )
        ),
        "three-field wrapper",
    )
    expect_rejection(
        _array(
            (
                _uint(PROTOCOL_ID, "protocol"),
                _uint(WIRE_VERSION, "version"),
                a_body_bytes,
                _bytes(a_root, "root", SHA256_SIZE),
                _uint(0, "extra"),
            )
        ),
        "five-field wrapper",
    )
    expect_rejection(
        _wrapper_from_encoded_body(a_body_bytes, a_root, protocol=PROTOCOL_ID + 1),
        "wrong protocol",
    )
    expect_rejection(
        _wrapper_from_encoded_body(a_body_bytes, a_root, version=WIRE_VERSION + 1),
        "wrong version",
    )

    moved_principal = list(a_body)
    moved_principal[29], moved_principal[30] = moved_principal[30], moved_principal[29]
    moved_principal_bytes = _generic_array_profile_encode(moved_principal)
    expect_rejection(
        _wrapper_from_encoded_body(
            moved_principal_bytes, compute_root(moved_principal_bytes)
        ),
        "BuildPrincipal moved from position 30",
    )
    moved_root = list(a_body)
    moved_root[4], moved_root[5] = moved_root[5], moved_root[4]
    moved_root[21], moved_root[22] = moved_root[22], moved_root[21]
    moved_root_bytes = _generic_array_profile_encode(moved_root)
    expect_rejection(
        _wrapper_from_encoded_body(moved_root_bytes, compute_root(moved_root_bytes)),
        "root custody moved from positions 4 and 21",
    )

    expect_rejection(
        _array(
            (
                _uint(PROTOCOL_ID, "protocol"),
                _uint(WIRE_VERSION, "version"),
                _bytes(a_body_bytes, "body as bytes"),
                _bytes(a_root, "root", SHA256_SIZE),
            )
        ),
        "body encoded as byte string",
    )
    expect_rejection(
        _array(
            (
                _uint(PROTOCOL_ID, "protocol"),
                _uint(WIRE_VERSION, "version"),
                a_body_bytes,
                _text_for_mutation(b"x" * SHA256_SIZE),
            )
        ),
        "root encoded as text",
    )
    for label, unsupported in (
        ("text", _text_for_mutation(b"x")),
        ("map", b"\xa0"),
        ("tag", b"\xc0\x00"),
        ("indefinite array", b"\x9f\xff"),
        ("boolean", b"\xf4"),
        ("null", b"\xf6"),
        ("floating point", b"\xf9\x00\x00"),
    ):
        expect_rejection(
            _array(
                (
                    _uint(PROTOCOL_ID, "protocol"),
                    _uint(WIRE_VERSION, "version"),
                    unsupported,
                    _bytes(a_root, "root", SHA256_SIZE),
                )
            ),
            label,
        )

    nonshortest_protocol = (
        b"\x84\x1b"
        + PROTOCOL_ID.to_bytes(8, "big")
        + _uint(WIRE_VERSION, "version")
        + a_body_bytes
        + _bytes(a_root, "root", SHA256_SIZE)
    )
    expect_rejection(nonshortest_protocol, "non-shortest integer")
    expect_rejection(b"\x00" + a_wrapper, "leading byte")
    expect_rejection(a_wrapper + b"\x00", "trailing byte")

    wrong_roots = (
        hashlib.sha256(b"V631302_STAGE1_EXTRACTION_CUSTODY_RECEIPT_V1\x00" + a_body_bytes).digest(),
        hashlib.sha256(DOMAIN_PREFIX[:-1] + a_body_bytes).digest(),
        hashlib.sha256(DOMAIN_PREFIX + b"\x00" + a_body_bytes).digest(),
        hashlib.sha256(a_wrapper).digest(),
        hashlib.sha256(_bytes(a_body_bytes, "body bstr")).digest(),
    )
    for index, wrong_root in enumerate(wrong_roots):
        expect_rejection(
            _wrapper_from_encoded_body(a_body_bytes, wrong_root),
            f"wrong root domain/scope {index}",
        )

    second_body = list(a_body)
    second_body[2], second_body[3] = second_body[3], second_body[2]
    second_body_bytes = _generic_array_profile_encode(second_body)
    expect_rejection(
        _wrapper_from_encoded_body(a_body_bytes, compute_root(second_body_bytes)),
        "root from a second body encoding",
    )
    reordered_body = _wrapper_from_encoded_body(
        second_body_bytes, compute_root(second_body_bytes)
    )
    reordered_view = verify_wrapper(reordered_body)
    if reordered_view.body_bytes == a_body_bytes or reordered_view.root == a_root:
        _fail("reordered same-typed body fields did not change bytes and root")

    mutated_body_bytes = bytearray(a_body_bytes)
    mutated_body_bytes[-1] ^= 1
    expect_rejection(
        _wrapper_from_encoded_body(bytes(mutated_body_bytes), a_root),
        "body byte changed after root computation",
    )
    mutated_wrapper = bytearray(a_wrapper)
    body_offset = a_wrapper.find(a_body_bytes)
    if body_offset < 0:
        _fail("test wrapper does not contain its exact body bytes")
    mutated_wrapper[body_offset + len(a_body_bytes) - 1] ^= 1
    expect_rejection(bytes(mutated_wrapper), "wrapper body byte mutation")

    # This import is used only as an independent semantic rejection oracle; no
    # encoder or root implementation is shared with the reference above.
    repository_root = Path(__file__).resolve().parents[6]
    if str(repository_root) not in sys.path:
        sys.path.insert(0, str(repository_root))
    from evaluation_v6_3_1.launch_gate_stage1_custody_receipt import (
        Stage1CustodyReceiptError,
        _file_identity as strict_file_identity,
        _final_listing as strict_final_listing,
        consume_stage1_extraction_custody_receipt,
    )

    for name, vector in vectors.items():
        try:
            consume_stage1_extraction_custody_receipt(vector["wrapper_bytes"])
        except Stage1CustodyReceiptError as error:
            if error.code != "RECEIPT_IMAGE_ID":
                _fail(f"strict consumer rejected vector {name} for {error.code}")
        else:
            _fail(f"strict consumer accepted non-evidentiary vector {name}")

    # The complete consumer deliberately stops at the all-zero image ID for
    # every offline vector. Exercise its independent cross-reference logic
    # directly as well, so Vector D is proven to fail for the listing/top-level
    # identity mismatch it was designed to carry rather than only for image ID.
    vector_d_body = vectors["D"]["body"]
    try:
        strict_final_listing(
            vector_d_body[26],
            strict_file_identity(vector_d_body[24], "vector_d.body[24]"),
            strict_file_identity(vector_d_body[25], "vector_d.body[25]"),
        )
    except Stage1CustodyReceiptError as error:
        if error.code != "RECEIPT_FINAL_LIST_CONTENT":
            _fail(f"strict cross-reference oracle rejected Vector D for {error.code}")
    else:
        _fail("strict cross-reference oracle accepted Vector D")


def _summary_line(name: str, vector: dict[str, object]) -> str:
    return (
        f"{name} body_len={len(vector['body_bytes'])} "
        f"wrapper_len={len(vector['wrapper_bytes'])} "
        f"body_sha256={vector['body_sha256']} "
        f"wrapper_sha256={vector['wrapper_sha256']} "
        f"root={vector['root'].hex()}"
    )


def compare_cpp_summary(executable: Path) -> None:
    """Require live agreement with summaries emitted by the current C++ test."""

    resolved = executable.resolve(strict=True)
    completed = subprocess.run(
        [str(resolved), "--emit-summary"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        _fail(
            "C++ summary command failed without exposing receipt bytes: "
            f"returncode={completed.returncode} stderr={completed.stderr.strip()!r}"
        )
    vectors = generate_vectors()
    expected = [_summary_line(name, vector) for name, vector in vectors.items()]
    actual = completed.stdout.splitlines()
    if actual != expected:
        _fail(
            "live C++/Python summary mismatch: "
            f"expected={expected!r} actual={actual!r}"
        )


if __name__ == "__main__":
    cpp_summary_path: Path | None = None
    if sys.argv[1:] == ["--self-test"] or not sys.argv[1:]:
        pass
    elif len(sys.argv) == 3 and sys.argv[1] == "--compare-cpp":
        cpp_summary_path = Path(sys.argv[2])
    else:
        _fail("usage: reference.py [--self-test | --compare-cpp CPP_TEST]")
    _self_test()
    if cpp_summary_path is not None:
        compare_cpp_summary(cpp_summary_path)
    for vector_name, vector_value in generate_vectors().items():
        print(_summary_line(vector_name, vector_value))


__all__ = [
    "BODY_FIELD_COUNT",
    "DOMAIN_PREFIX",
    "PROTOCOL_ID",
    "ReferenceError",
    "SHA256_SIZE",
    "UINT32_MAX",
    "UINT64_MAX",
    "WIRE_VERSION",
    "WrapperView",
    "ZERO_IMAGE_ID",
    "compute_root",
    "compare_cpp_summary",
    "encode_blob_digest",
    "encode_body",
    "encode_build_principal",
    "encode_byte_array",
    "encode_census",
    "encode_cwd_identity",
    "encode_directory_identity",
    "encode_file_identity",
    "encode_final_directory_listing",
    "encode_mount_info",
    "encode_namespace_identity",
    "encode_object_identity",
    "encode_root_mount_custody",
    "encode_seccomp_policy",
    "encode_wrapper",
    "extract_body_bytes",
    "generate_vectors",
    "make_vectors",
    "parse_strict_wrapper",
    "recompute_root",
    "verify_wrapper",
    "vector_a",
    "vector_b",
    "vector_c",
    "vector_d",
]
