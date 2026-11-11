from __future__ import annotations

import hashlib

import pytest

from evaluation_v6_3_1.canonical_trace_codec import (
    CanonicalTraceCodecError,
    canonical_cbor_decode,
    canonical_cbor_encode,
    domain_sha256,
)


def _assert_code(code: str, function, *args) -> None:
    with pytest.raises(CanonicalTraceCodecError) as raised:
        function(*args)
    assert raised.value.code == code


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (None, "f6"),
        (False, "f4"),
        (True, "f5"),
        (0, "00"),
        (23, "17"),
        (24, "1818"),
        (255, "18ff"),
        (256, "190100"),
        (-1, "20"),
        (-24, "37"),
        (-25, "3818"),
        (b"", "40"),
        (b"abc", "43616263"),
        ("A", "6141"),
        ([1, "a", None], "83016161f6"),
        ({"b": 2, "a": 1}, "a2616101616202"),
    ),
)
def test_golden_canonical_bytes(value, expected: str) -> None:
    assert canonical_cbor_encode(value) == bytes.fromhex(expected)


def test_round_trip_supported_trace_values() -> None:
    value = {
        "schema": "eval.v6.3.1.trace.v1",
        "flags": [True, False, None],
        "count": -7,
        "digest": bytes(range(8)),
        "unicode": "café",
        "nested": {"items": [0, 24, 256]},
    }
    encoded = canonical_cbor_encode(value)
    assert canonical_cbor_decode(encoded) == value
    assert canonical_cbor_encode(canonical_cbor_decode(encoded)) == encoded


def test_nfc_is_required_on_encode_and_decode() -> None:
    decomposed = "cafe\u0301"
    _assert_code("TRACE_NONCANONICAL_ENCODING", canonical_cbor_encode, decomposed)
    # 66 63 61 66 65 cc 81 is valid UTF-8 but not NFC.
    _assert_code("TRACE_NONCANONICAL_ENCODING", canonical_cbor_decode, bytes.fromhex("6663616665cc81"))
    assert canonical_cbor_decode(canonical_cbor_encode("café")) == "café"


@pytest.mark.parametrize(
    "raw",
    (
        "1800",  # non-minimal integer
        "190017",  # non-minimal two-byte integer
        "3800",  # non-minimal negative integer
        "7801",  # truncated text payload
        "61ff",  # invalid UTF-8
        "9f0180ff",  # indefinite-length array
        "c001",  # tag
        "fb3ff0000000000000",  # float
        "a2616202616101",  # map keys not in canonical order
        "a2616101616102",  # duplicate map key
        "00ff",  # trailing bytes
    ),
)
def test_noncanonical_and_unsupported_wire_forms_are_rejected(raw: str) -> None:
    _assert_code("TRACE_NONCANONICAL_ENCODING", canonical_cbor_decode, bytes.fromhex(raw))


def test_map_order_uses_encoded_key_length_then_bytes() -> None:
    # The one-byte text key sorts before the two-byte integer key under the
    # deterministic CBOR ordering, despite integer major-type precedence.
    encoded = canonical_cbor_encode({24: "integer", "": "text"})
    assert encoded == bytes.fromhex("a2606474657874181867696e7465676572")
    assert canonical_cbor_decode(encoded) == {24: "integer", "": "text"}
    _assert_code(
        "TRACE_NONCANONICAL_ENCODING",
        canonical_cbor_decode,
        bytes.fromhex("a2181867696e7465676572606574657874"),
    )


@pytest.mark.parametrize("value", (0.5, {1, 2}, bytearray(b"x"), object()))
def test_unsupported_python_types_fail_closed(value) -> None:
    _assert_code("TRACE_UNSUPPORTED_TYPE", canonical_cbor_encode, value)


def test_boolean_is_not_encoded_as_an_integer() -> None:
    assert canonical_cbor_encode(True) == b"\xf5"
    assert canonical_cbor_encode(False) == b"\xf4"
    assert canonical_cbor_decode(b"\xf5") is True
    assert canonical_cbor_decode(b"\xf4") is False


def test_cycles_and_resource_limits_fail_closed() -> None:
    cyclic = []
    cyclic.append(cyclic)
    _assert_code("TRACE_NONCANONICAL_ENCODING", canonical_cbor_encode, cyclic)

    nested = None
    for _ in range(65):
        nested = [nested]
    _assert_code("TRACE_CODEC_RESOURCE_LIMIT", canonical_cbor_encode, nested)
    _assert_code("TRACE_CODEC_RESOURCE_LIMIT", canonical_cbor_encode, b"x" * (1 << 20 | 1))
    _assert_code("TRACE_CODEC_RESOURCE_LIMIT", canonical_cbor_decode, bytes.fromhex("5a01000001"))


def test_domain_sha256_hashes_the_canonical_value() -> None:
    domain = b"V631/TRACE/HEADER"
    value = {"a": 1}
    expected = hashlib.sha256(domain + canonical_cbor_encode(value)).hexdigest()
    assert domain_sha256(domain, value) == expected
    _assert_code("TRACE_UNSUPPORTED_TYPE", domain_sha256, "domain", value)
