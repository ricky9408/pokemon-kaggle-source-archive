from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from evaluation_v4_1.beacon import (
    BeaconVerificationError,
    _normalize_pulse,
    _serialize_unsigned,
    build_beacon_receipt,
    validate_beacon_receipt,
    write_beacon_receipt_once,
)
from tests.test_evaluation_v4_1_prediction import _model, _protocol


def _run(*args: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ["openssl", *args],
        input=input_bytes,
        capture_output=True,
        check=True,
    ).stdout


def _certificate(tmp_path: Path) -> tuple[Path, str, str]:
    key = tmp_path / "key.pem"
    certificate = tmp_path / "certificate.pem"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "engine.beacon.nist.gov")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
        .sign(private_key, hashes.SHA256())
    )
    key.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem = certificate.read_text(encoding="ascii")
    der = _run("x509", "-in", str(certificate), "-outform", "DER")
    return key, pem, hashlib.sha512(der).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _pulse(
    *,
    key: Path,
    certificate_id: str,
    index: int,
    timestamp: datetime,
    previous_output: str,
) -> dict[str, object]:
    uri = f"https://beacon.nist.gov/beacon/2.0/chain/2/pulse/{index}"
    pulse: dict[str, object] = {
        "uri": uri,
        "version": "2.0",
        "cipherSuite": 0,
        "period": 60000,
        "certificateId": certificate_id,
        "chainIndex": 2,
        "pulseIndex": index,
        "timeStamp": _timestamp(timestamp),
        "localRandomValue": f"{index + 1:0128x}",
        "external": {
            "sourceId": "0" * 128,
            "statusCode": 0,
            "value": "0" * 128,
        },
        "listValues": [
            {
                "uri": f"https://beacon.nist.gov/beacon/2.0/chain/2/pulse/{index - 1}",
                "type": "previous",
                "value": previous_output,
            },
            {"uri": uri, "type": "hour", "value": "1" * 128},
            {"uri": uri, "type": "day", "value": "2" * 128},
            {"uri": uri, "type": "month", "value": "3" * 128},
            {"uri": uri, "type": "year", "value": "4" * 128},
        ],
        "precommitmentValue": "5" * 128,
        "statusCode": 0,
        "signatureValue": "0" * 1024,
        "outputValue": "0" * 128,
    }
    unsigned = _serialize_unsigned(_normalize_pulse(pulse))
    message = key.parent / f"message-{index}.bin"
    signature = key.parent / f"signature-{index}.bin"
    message.write_bytes(unsigned)
    subprocess.run(
        ["openssl", "dgst", "-sha512", "-sign", str(key), "-out", str(signature), str(message)],
        capture_output=True,
        check=True,
    )
    signature_bytes = signature.read_bytes()
    assert len(signature_bytes) == 512
    pulse["signatureValue"] = signature_bytes.hex()
    pulse["outputValue"] = hashlib.sha512(unsigned + signature_bytes).hexdigest()
    return pulse


def _fixture(tmp_path: Path) -> tuple[dict[str, object], dict[str, object]]:
    key, certificate, certificate_id = _certificate(tmp_path)
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    previous_time = now + timedelta(minutes=1)
    current_time = now + timedelta(minutes=2)
    anchor = previous_time - timedelta(seconds=90)
    previous = _pulse(
        key=key,
        certificate_id=certificate_id,
        index=10,
        timestamp=previous_time,
        previous_output="0" * 128,
    )
    current = _pulse(
        key=key,
        certificate_id=certificate_id,
        index=11,
        timestamp=current_time,
        previous_output=previous["outputValue"],  # type: ignore[arg-type]
    )
    protocol = _protocol(_model())
    kwargs = {
        "protocol": protocol,
        "anchor_granted_at_utc": anchor.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "current_pulse": current,
        "previous_pulse": previous,
        "current_certificate_pem": certificate,
        "previous_certificate_pem": certificate,
        "fetched_at_utc": (current_time + timedelta(minutes=1)).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ),
        "openssl_bin": "openssl",
    }
    return build_beacon_receipt(**kwargs), kwargs


def test_signed_consecutive_boundary_pair_builds_recomputable_receipt(tmp_path: Path) -> None:
    receipt, kwargs = _fixture(tmp_path)
    assert receipt["verification"] == {
        "current_signature": True,
        "previous_signature": True,
        "current_output": True,
        "previous_output": True,
        "current_certificate_id": True,
        "previous_certificate_id": True,
        "chain_link": True,
        "boundary": True,
    }
    assert len(receipt["external_beacon_sha256"]) == 64
    assert receipt["external_beacon_round"] == "chain-2-pulse-11"
    assert validate_beacon_receipt(receipt, protocol=kwargs["protocol"]) == receipt


def test_signature_output_certificate_and_chain_mutations_fail(tmp_path: Path) -> None:
    receipt, kwargs = _fixture(tmp_path)
    mutations = []
    changed = copy.deepcopy(receipt)
    changed["current_pulse"]["outputValue"] = "9" * 128
    mutations.append(changed)
    changed = copy.deepcopy(receipt)
    changed["current_pulse"]["signatureValue"] = "9" * 1024
    mutations.append(changed)
    changed = copy.deepcopy(receipt)
    changed["current_pulse"]["certificateId"] = "9" * 128
    mutations.append(changed)
    changed = copy.deepcopy(receipt)
    next(item for item in changed["current_pulse"]["listValues"] if item["type"] == "previous")[
        "value"
    ] = "9" * 128
    mutations.append(changed)
    for mutation in mutations:
        with pytest.raises(BeaconVerificationError):
            validate_beacon_receipt(mutation, protocol=kwargs["protocol"])


def test_cutoff_cannot_be_moved_to_choose_a_later_pulse(tmp_path: Path) -> None:
    receipt, kwargs = _fixture(tmp_path)
    changed = copy.deepcopy(receipt)
    changed["anchor_granted_at_utc"] = receipt["current_pulse"]["timeStamp"]
    with pytest.raises(BeaconVerificationError, match="boundary"):
        validate_beacon_receipt(changed, protocol=kwargs["protocol"])


def test_receipt_is_research_only_and_create_once(tmp_path: Path) -> None:
    receipt, kwargs = _fixture(tmp_path)
    assert receipt["research_only"] is True
    assert receipt["production_submission_authorized"] is False
    output = tmp_path / "receipt.json"
    assert write_beacon_receipt_once(output, receipt, protocol=kwargs["protocol"]) == output
    with pytest.raises(FileExistsError):
        write_beacon_receipt_once(output, receipt, protocol=kwargs["protocol"])
