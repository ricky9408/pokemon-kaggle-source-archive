from __future__ import annotations

import base64
import copy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1.canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from evaluation_v5_1.envelope import EnvelopeError, build_envelope, signing_payload, verify_envelope
from evaluation_v5_1.exact_gate_v2 import _decode_ed25519_point, _ed25519_add


SCHEMA = "evaluation_v5_1_test_artifact_v1"
ED25519_L = 2**252 + 27742317777372353535851937790883648493


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public


def _envelope() -> tuple[dict[str, object], bytes]:
    private, public = _keypair()
    payload = {"archive_sha256": "a" * 64, "count": 3}
    from evaluation_v5_1.canonical import canonical_sha256

    signature = private.sign(signing_payload(SCHEMA, canonical_sha256(payload)))
    return build_envelope(
        artifact_schema=SCHEMA,
        payload=payload,
        signer_public_key_bytes=public,
        signature=signature,
    ), public


def test_round_trip_verifies_pinned_key_and_payload() -> None:
    envelope, public = _envelope()
    assert verify_envelope(
        envelope, expected_artifact_schema=SCHEMA, pinned_public_key_bytes=public
    ) == {"archive_sha256": "a" * 64, "count": 3}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("payload_sha256", "b" * 64),
        ("artifact_schema", "evaluation_v5_1_other_v1"),
        ("signer_key_fingerprint_sha256", "c" * 64),
    ],
)
def test_bound_fields_cannot_be_changed(field: str, value: object) -> None:
    envelope, public = _envelope()
    envelope[field] = value
    with pytest.raises(EnvelopeError):
        verify_envelope(envelope, expected_artifact_schema=SCHEMA, pinned_public_key_bytes=public)


def test_payload_tampering_is_rejected() -> None:
    envelope, public = _envelope()
    tampered = copy.deepcopy(envelope)
    tampered["payload"]["count"] = 4  # type: ignore[index]
    with pytest.raises(EnvelopeError, match="payload_sha256"):
        verify_envelope(tampered, expected_artifact_schema=SCHEMA, pinned_public_key_bytes=public)


def test_wrong_key_is_rejected() -> None:
    envelope, _ = _envelope()
    _, other_public = _keypair()
    with pytest.raises(EnvelopeError, match="pinned key"):
        verify_envelope(
            envelope, expected_artifact_schema=SCHEMA, pinned_public_key_bytes=other_public
        )


def test_extra_field_is_rejected() -> None:
    envelope, public = _envelope()
    envelope["authority"] = True
    with pytest.raises(EnvelopeError, match="fields are not exact"):
        verify_envelope(envelope, expected_artifact_schema=SCHEMA, pinned_public_key_bytes=public)


def test_canonical_json_rejects_nonfinite_and_python_conveniences() -> None:
    with pytest.raises(CanonicalJSONError):
        canonical_json_bytes({"bad": float("nan")})
    with pytest.raises(CanonicalJSONError):
        canonical_json_bytes({"bad": (1, 2)})


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _torsion_points() -> list[tuple[int, int]]:
    order8 = _decode_ed25519_point(
        bytes.fromhex(
            "26e8958fc2b227b045c3f489f2ef98f0"
            "d5dfac05d3c63339b13802886d53fc05"
        ),
        label="torsion generator",
        reject_small_order=False,
    )
    points: list[tuple[int, int]] = []
    point = (0, 1)
    for _ in range(8):
        points.append(point)
        point = _ed25519_add(point, order8)
    assert point == (0, 1)
    return points


def test_build_rejects_noncanonical_and_small_order_public_keys() -> None:
    private, public = _keypair()
    payload = {"archive_sha256": "a" * 64}
    signature = private.sign(signing_payload(SCHEMA, canonical_sha256(payload)))
    bad_keys = [
        bytes.fromhex("ed" + "ff" * 30 + "7f"),  # y == p
        b"\x01" + bytes(31),  # identity, order one
    ]
    for bad_key in bad_keys:
        with pytest.raises(EnvelopeError, match="strict Ed25519 public key"):
            build_envelope(
                artifact_schema=SCHEMA,
                payload=payload,
                signer_public_key_bytes=bad_key,
                signature=signature,
            )

    public_point = _decode_ed25519_point(public, label="valid public", reject_small_order=True)
    mixed_key = _encode_point(_ed25519_add(public_point, _torsion_points()[1]))
    with pytest.raises(EnvelopeError, match="prime-order subgroup"):
        build_envelope(
            artifact_schema=SCHEMA,
            payload=payload,
            signer_public_key_bytes=mixed_key,
            signature=signature,
        )


def test_verify_rejects_noncanonical_small_order_and_mixed_order_public_keys() -> None:
    envelope, public = _envelope()
    public_point = _decode_ed25519_point(public, label="valid public", reject_small_order=True)
    bad_keys = [
        bytes.fromhex("ed" + "ff" * 30 + "7f"),
        b"\x01" + bytes(31),
        _encode_point(_ed25519_add(public_point, _torsion_points()[1])),
    ]
    for bad_key in bad_keys:
        with pytest.raises(EnvelopeError, match="strict Ed25519 public key"):
            verify_envelope(
                envelope,
                expected_artifact_schema=SCHEMA,
                pinned_public_key_bytes=bad_key,
            )


@pytest.mark.parametrize("bad_signature", [
    bytes.fromhex("ed" + "ff" * 30 + "7f") + bytes(32),  # noncanonical R
    b"\x01" + bytes(31) + bytes(32),  # small-order R
])
def test_build_rejects_noncanonical_or_small_order_r_points(bad_signature: bytes) -> None:
    _, public = _keypair()
    with pytest.raises(EnvelopeError, match="strict Ed25519 encoding"):
        build_envelope(
            artifact_schema=SCHEMA,
            payload={"archive_sha256": "a" * 64},
            signer_public_key_bytes=public,
            signature=bad_signature,
        )


def test_build_and_verify_reject_adversarial_r_and_noncanonical_s() -> None:
    private, public = _keypair()
    payload = {"archive_sha256": "a" * 64}
    valid_signature = private.sign(signing_payload(SCHEMA, canonical_sha256(payload)))
    r_point = _decode_ed25519_point(valid_signature[:32], label="valid R", reject_small_order=True)
    mixed_r = _encode_point(_ed25519_add(r_point, _torsion_points()[1]))
    bad_signatures = (
        bytes.fromhex("ed" + "ff" * 30 + "7f") + valid_signature[32:],
        b"\x01" + bytes(31) + valid_signature[32:],
        mixed_r + valid_signature[32:],
        valid_signature[:32] + ED25519_L.to_bytes(32, "little"),
        valid_signature[:32]
        + (ED25519_L + 1).to_bytes(32, "little"),
    )
    for bad_signature in bad_signatures:
        with pytest.raises(EnvelopeError, match="strict Ed25519 encoding"):
            build_envelope(
                artifact_schema=SCHEMA,
                payload=payload,
                signer_public_key_bytes=public,
                signature=bad_signature,
            )

    envelope = build_envelope(
        artifact_schema=SCHEMA,
        payload=payload,
        signer_public_key_bytes=public,
        signature=valid_signature,
    )
    for bad_signature in bad_signatures:
        tampered = copy.deepcopy(envelope)
        tampered["signature_ed25519_base64"] = base64.b64encode(bad_signature).decode("ascii")
        with pytest.raises(EnvelopeError, match="strict Ed25519 encoding"):
            verify_envelope(
                tampered,
                expected_artifact_schema=SCHEMA,
                pinned_public_key_bytes=public,
            )


def test_build_rejects_bool_and_noncanonical_crypto_inputs() -> None:
    private, public = _keypair()
    payload = {"archive_sha256": "a" * 64}
    valid_signature = private.sign(signing_payload(SCHEMA, canonical_sha256(payload)))
    cases = ((True, valid_signature), (public, True), (b"\x00" * 31, b"\x00" * 64))
    for public_key, signature in cases:
        with pytest.raises(EnvelopeError):
            build_envelope(
                artifact_schema=SCHEMA,
                payload=payload,
                signer_public_key_bytes=public_key,  # type: ignore[arg-type]
                signature=signature,  # type: ignore[arg-type]
            )


def test_verify_rejects_bool_key_and_noncanonical_base64_before_crypto() -> None:
    envelope, public = _envelope()
    with pytest.raises(EnvelopeError, match="pinned public key"):
        verify_envelope(
            envelope, expected_artifact_schema=SCHEMA, pinned_public_key_bytes=True  # type: ignore[arg-type]
        )
    malformed = copy.deepcopy(envelope)
    malformed["signature_ed25519_base64"] = True
    with pytest.raises(EnvelopeError, match="signature_ed25519_base64 must be a string"):
        verify_envelope(
            malformed,
            expected_artifact_schema=SCHEMA,
            pinned_public_key_bytes=public,
        )
