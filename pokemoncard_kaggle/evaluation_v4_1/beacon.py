"""Cryptographic NIST Beacon v2 boundary receipt for VOI-P5 assignment.

The protocol selects the first signed pulse strictly after a timestamp-derived
cutoff.  A verified immediately preceding pulse proves that the operator did
not choose among several later outputs.  The resulting SHA-256 is only an
assignment seed; it is never performance evidence or submission authority.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Callable, Mapping
from urllib.parse import urlparse
from urllib.request import urlopen

from .protocol import canonical_json_bytes, canonical_sha256, validate_protocol


RECEIPT_SCHEMA = "nist_beacon_v2_boundary_receipt_v1"
_SOURCE = "https://beacon.nist.gov/beacon/2.0"
_PULSE_FIELDS = frozenset(
    {
        "uri",
        "version",
        "cipherSuite",
        "period",
        "certificateId",
        "chainIndex",
        "pulseIndex",
        "timeStamp",
        "localRandomValue",
        "external",
        "listValues",
        "precommitmentValue",
        "statusCode",
        "signatureValue",
        "outputValue",
    }
)
_EXTERNAL_FIELDS = frozenset({"sourceId", "statusCode", "value"})
_LIST_FIELDS = frozenset({"uri", "type", "value"})
_LIST_TYPES = ("previous", "hour", "day", "month", "year")
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "protocol_sha256",
        "anchor_granted_at_utc",
        "delay_seconds",
        "cutoff_at_utc",
        "selection_query_url",
        "current_pulse",
        "previous_pulse",
        "current_certificate_pem",
        "previous_certificate_pem",
        "current_pulse_sha256",
        "previous_pulse_sha256",
        "external_beacon_sha256",
        "output_value_sha512",
        "external_beacon_round",
        "fetched_at_utc",
        "verification",
        "research_only",
        "production_submission_authorized",
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}
_VERIFICATION_FIELDS = frozenset(
    {
        "current_signature",
        "previous_signature",
        "current_output",
        "previous_output",
        "current_certificate_id",
        "previous_certificate_id",
        "chain_link",
        "boundary",
    }
)
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class BeaconVerificationError(ValueError):
    """A NIST pulse, certificate, chain link, or cutoff boundary is invalid."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise BeaconVerificationError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BeaconVerificationError(f"{label} must be a nonnegative integer")
    return value


def _hex(value: object, *, label: str, byte_length: int) -> str:
    if not isinstance(value, str) or len(value) != byte_length * 2 or _HEX_RE.fullmatch(value) is None:
        raise BeaconVerificationError(f"{label} must be exactly {byte_length} hexadecimal bytes")
    return value.upper()


def _parse_utc(value: object, *, label: str) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BeaconVerificationError(f"{label} must be UTC with a Z suffix")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise BeaconVerificationError(f"{label} is invalid") from exc
    return parsed, parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise BeaconVerificationError(f"{label} must be a lowercase SHA-256")
    return value


def _strict_official_url(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise BeaconVerificationError(f"{label} must be an official HTTPS URL")
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != "beacon.nist.gov" or parsed.port is not None:
        raise BeaconVerificationError(f"{label} must use https://beacon.nist.gov")
    if parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query:
        raise BeaconVerificationError(f"{label} contains prohibited URL components")
    return value


def _string_bytes(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return len(encoded).to_bytes(4, "big") + encoded


def _hash_bytes(value: str) -> bytes:
    encoded = bytes.fromhex(value)
    return len(encoded).to_bytes(4, "big") + encoded


def _list_values(pulse: Mapping[str, Any]) -> dict[str, str]:
    values = pulse["listValues"]
    if not isinstance(values, list) or len(values) != len(_LIST_TYPES):
        raise BeaconVerificationError("pulse listValues must contain exactly five entries")
    result: dict[str, str] = {}
    for raw in values:
        item = _exact_fields(raw, _LIST_FIELDS, label="pulse list value")
        kind = item["type"]
        if kind not in _LIST_TYPES or kind in result:
            raise BeaconVerificationError("pulse listValues types must be unique and complete")
        _strict_official_url(item["uri"], label="pulse list value uri")
        result[kind] = _hex(item["value"], label=f"pulse list value {kind}", byte_length=64)
    if set(result) != set(_LIST_TYPES):
        raise BeaconVerificationError("pulse listValues types are incomplete")
    return result


def _normalize_pulse(pulse: object) -> dict[str, Any]:
    raw = _exact_fields(pulse, _PULSE_FIELDS, label="pulse")
    chain_index = _integer(raw["chainIndex"], label="chainIndex")
    pulse_index = _integer(raw["pulseIndex"], label="pulseIndex")
    uri = _strict_official_url(raw["uri"], label="pulse uri")
    expected_uri = f"{_SOURCE}/chain/{chain_index}/pulse/{pulse_index}"
    if uri != expected_uri:
        raise BeaconVerificationError("pulse uri does not match chain and pulse indices")
    if raw["version"] != "2.0" or raw["cipherSuite"] != 0 or raw["period"] != 60000:
        raise BeaconVerificationError("only the deployed NIST v2 cipher-suite-0 minute pulse is supported")
    external = _exact_fields(raw["external"], _EXTERNAL_FIELDS, label="pulse external")
    normalized_external = {
        "sourceId": _hex(external["sourceId"], label="external.sourceId", byte_length=64),
        "statusCode": _integer(external["statusCode"], label="external.statusCode"),
        "value": _hex(external["value"], label="external.value", byte_length=64),
    }
    timestamp, _ = _parse_utc(raw["timeStamp"], label="pulse timeStamp")
    if timestamp.microsecond % 1000:
        raise BeaconVerificationError("pulse timeStamp must have millisecond precision")
    list_values = _list_values(raw)
    ordered_list = [next(item for item in raw["listValues"] if item["type"] == kind) for kind in _LIST_TYPES]
    signature = _hex(raw["signatureValue"], label="signatureValue", byte_length=512)
    return {
        "uri": uri,
        "version": "2.0",
        "cipherSuite": 0,
        "period": 60000,
        "certificateId": _hex(raw["certificateId"], label="certificateId", byte_length=64),
        "chainIndex": chain_index,
        "pulseIndex": pulse_index,
        "timeStamp": raw["timeStamp"],
        "localRandomValue": _hex(raw["localRandomValue"], label="localRandomValue", byte_length=64),
        "external": normalized_external,
        "listValues": [
            {
                "uri": _strict_official_url(item["uri"], label="list value uri"),
                "type": item["type"],
                "value": list_values[item["type"]],
            }
            for item in ordered_list
        ],
        "precommitmentValue": _hex(
            raw["precommitmentValue"], label="precommitmentValue", byte_length=64
        ),
        "statusCode": _integer(raw["statusCode"], label="statusCode"),
        "signatureValue": signature,
        "outputValue": _hex(raw["outputValue"], label="outputValue", byte_length=64),
    }


def _serialize_unsigned(pulse: Mapping[str, Any]) -> bytes:
    values = {item["type"]: item["value"] for item in pulse["listValues"]}
    external = pulse["external"]
    return b"".join(
        (
            _string_bytes(pulse["uri"]),
            _string_bytes(pulse["version"]),
            pulse["cipherSuite"].to_bytes(4, "big"),
            pulse["period"].to_bytes(4, "big"),
            _hash_bytes(pulse["certificateId"]),
            pulse["chainIndex"].to_bytes(8, "big"),
            pulse["pulseIndex"].to_bytes(8, "big"),
            _string_bytes(pulse["timeStamp"]),
            _hash_bytes(pulse["localRandomValue"]),
            _hash_bytes(external["sourceId"]),
            external["statusCode"].to_bytes(4, "big"),
            _hash_bytes(external["value"]),
            _hash_bytes(values["previous"]),
            _hash_bytes(values["hour"]),
            _hash_bytes(values["day"]),
            _hash_bytes(values["month"]),
            _hash_bytes(values["year"]),
            _hash_bytes(pulse["precommitmentValue"]),
            pulse["statusCode"].to_bytes(4, "big"),
        )
    )


def _run_openssl(args: list[str], *, input_bytes: bytes | None = None, openssl_bin: str) -> bytes:
    if not openssl_bin or Path(openssl_bin).name != openssl_bin:
        raise BeaconVerificationError("openssl_bin must be a bare executable name")
    completed = subprocess.run(
        [openssl_bin, *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise BeaconVerificationError(f"OpenSSL verification failed: {detail}")
    return completed.stdout


def _certificate_metadata(certificate_pem: str, *, openssl_bin: str) -> tuple[bytes, datetime, datetime, str]:
    certificate = certificate_pem.encode("ascii")
    der = _run_openssl(["x509", "-outform", "DER"], input_bytes=certificate, openssl_bin=openssl_bin)
    details = _run_openssl(
        ["x509", "-noout", "-dates", "-subject", "-nameopt", "RFC2253"],
        input_bytes=certificate,
        openssl_bin=openssl_bin,
    ).decode("ascii", errors="strict")
    fields = dict(line.split("=", 1) for line in details.splitlines() if "=" in line)
    try:
        not_before = parsedate_to_datetime(fields["notBefore"]).astimezone(timezone.utc)
        not_after = parsedate_to_datetime(fields["notAfter"]).astimezone(timezone.utc)
        subject = fields["subject"]
    except (KeyError, TypeError, ValueError) as exc:
        raise BeaconVerificationError("certificate dates or subject are unavailable") from exc
    if "CN=engine.beacon.nist.gov" not in subject:
        raise BeaconVerificationError("certificate subject is not the NIST beacon engine")
    return der, not_before, not_after, subject


def _verify_pulse(pulse: object, certificate_pem: object, *, openssl_bin: str) -> dict[str, Any]:
    normalized = _normalize_pulse(pulse)
    if not isinstance(certificate_pem, str) or "-----BEGIN CERTIFICATE-----" not in certificate_pem:
        raise BeaconVerificationError("certificate_pem is invalid")
    try:
        certificate_pem.encode("ascii")
    except UnicodeEncodeError as exc:
        raise BeaconVerificationError("certificate_pem must be ASCII") from exc
    unsigned = _serialize_unsigned(normalized)
    signature = bytes.fromhex(normalized["signatureValue"])
    output = hashlib.sha512(unsigned + signature).hexdigest().upper()
    if output != normalized["outputValue"]:
        raise BeaconVerificationError("pulse outputValue does not match signed content")
    der, not_before, not_after, _ = _certificate_metadata(certificate_pem, openssl_bin=openssl_bin)
    certificate_id = hashlib.sha512(der).hexdigest().upper()
    if certificate_id != normalized["certificateId"]:
        raise BeaconVerificationError("pulse certificateId does not match certificate DER")
    pulse_time = _parse_utc(normalized["timeStamp"], label="pulse timeStamp")[0]
    if not not_before <= pulse_time <= not_after:
        raise BeaconVerificationError("pulse timestamp is outside certificate validity")
    with tempfile.TemporaryDirectory(prefix="voi-p5-beacon-") as directory:
        root = Path(directory)
        cert_path = root / "certificate.pem"
        message_path = root / "message.bin"
        signature_path = root / "signature.bin"
        public_key_path = root / "public-key.pem"
        cert_path.write_text(certificate_pem, encoding="ascii")
        message_path.write_bytes(unsigned)
        signature_path.write_bytes(signature)
        public_key_path.write_bytes(
            _run_openssl(["x509", "-pubkey", "-noout", "-in", str(cert_path)], openssl_bin=openssl_bin)
        )
        verified = _run_openssl(
            [
                "dgst",
                "-sha512",
                "-verify",
                str(public_key_path),
                "-signature",
                str(signature_path),
                str(message_path),
            ],
            openssl_bin=openssl_bin,
        )
        if b"Verified OK" not in verified:
            raise BeaconVerificationError("OpenSSL did not report a verified pulse signature")
    return normalized


def _build_content(
    *,
    protocol: object,
    anchor_granted_at_utc: str,
    current_pulse: object,
    previous_pulse: object,
    current_certificate_pem: str,
    previous_certificate_pem: str,
    fetched_at_utc: str,
    openssl_bin: str,
) -> dict[str, Any]:
    frozen = validate_protocol(protocol)
    if frozen["external_beacon_source"] != _SOURCE:
        raise BeaconVerificationError("protocol does not bind the official NIST beacon source")
    anchor, anchor_text = _parse_utc(anchor_granted_at_utc, label="anchor_granted_at_utc")
    delay = frozen["external_beacon_delay_seconds"]
    cutoff = anchor + timedelta(seconds=delay)
    current = _verify_pulse(current_pulse, current_certificate_pem, openssl_bin=openssl_bin)
    previous = _verify_pulse(previous_pulse, previous_certificate_pem, openssl_bin=openssl_bin)
    current_time = _parse_utc(current["timeStamp"], label="current pulse timeStamp")[0]
    previous_time = _parse_utc(previous["timeStamp"], label="previous pulse timeStamp")[0]
    if current["chainIndex"] != previous["chainIndex"] or current["pulseIndex"] != previous["pulseIndex"] + 1:
        raise BeaconVerificationError("pulses are not consecutive in one chain")
    current_previous = next(item["value"] for item in current["listValues"] if item["type"] == "previous")
    if current_previous != previous["outputValue"]:
        raise BeaconVerificationError("current pulse does not hash-link to previous pulse")
    if not previous_time <= cutoff < current_time:
        raise BeaconVerificationError("signed pulse pair does not prove the fixed selection boundary")
    fetched, fetched_text = _parse_utc(fetched_at_utc, label="fetched_at_utc")
    if fetched < current_time:
        raise BeaconVerificationError("fetched_at_utc cannot precede the selected pulse")
    cutoff_ms = int(cutoff.timestamp() * 1000) + 1
    query_url = f"{_SOURCE}/pulse/time/next/{cutoff_ms}"
    output_bytes = bytes.fromhex(current["outputValue"])
    beacon_sha = hashlib.sha256(output_bytes).hexdigest()
    verification = {field: True for field in _VERIFICATION_FIELDS}
    return {
        "schema": RECEIPT_SCHEMA,
        "protocol_sha256": canonical_sha256(frozen),
        "anchor_granted_at_utc": anchor_text,
        "delay_seconds": delay,
        "cutoff_at_utc": cutoff.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "selection_query_url": query_url,
        "current_pulse": current,
        "previous_pulse": previous,
        "current_certificate_pem": current_certificate_pem,
        "previous_certificate_pem": previous_certificate_pem,
        "current_pulse_sha256": canonical_sha256(current),
        "previous_pulse_sha256": canonical_sha256(previous),
        "external_beacon_sha256": beacon_sha,
        "output_value_sha512": current["outputValue"].lower(),
        "external_beacon_round": f"chain-{current['chainIndex']}-pulse-{current['pulseIndex']}",
        "fetched_at_utc": fetched_text,
        "verification": verification,
        "research_only": True,
        "production_submission_authorized": False,
    }


def build_beacon_receipt(**kwargs: object) -> dict[str, Any]:
    """Build and cryptographically verify a fixed-boundary beacon receipt."""

    content = _build_content(**kwargs)  # type: ignore[arg-type]
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_beacon_receipt(
    value: object,
    *,
    protocol: object,
    openssl_bin: str = "openssl",
) -> dict[str, Any]:
    raw = _exact_fields(value, _FIELDS, label="beacon receipt")
    if raw["schema"] != RECEIPT_SCHEMA:
        raise BeaconVerificationError("beacon receipt schema mismatch")
    expected = _build_content(
        protocol=protocol,
        anchor_granted_at_utc=raw["anchor_granted_at_utc"],
        current_pulse=raw["current_pulse"],
        previous_pulse=raw["previous_pulse"],
        current_certificate_pem=raw["current_certificate_pem"],
        previous_certificate_pem=raw["previous_certificate_pem"],
        fetched_at_utc=raw["fetched_at_utc"],
        openssl_bin=openssl_bin,
    )
    if {field: raw[field] for field in _CONTENT_FIELDS} != expected:
        raise BeaconVerificationError("beacon receipt is not the exact recomputed receipt")
    content_sha = _sha(raw["content_sha256"], label="content_sha256")
    if content_sha != canonical_sha256(expected):
        raise BeaconVerificationError("beacon receipt content_sha256 mismatch")
    return {**expected, "content_sha256": content_sha}


def _fetch_json(url: str, *, opener: Callable[..., Any], timeout: float) -> dict[str, Any]:
    _strict_official_url(url, label="fetch URL")
    with opener(url, timeout=timeout) as response:
        payload = response.read()
    try:
        wrapper = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BeaconVerificationError("NIST pulse response is not JSON") from exc
    if not isinstance(wrapper, Mapping) or set(wrapper) != {"pulse"}:
        raise BeaconVerificationError("NIST pulse response wrapper is invalid")
    return dict(wrapper["pulse"])


def _fetch_text(url: str, *, opener: Callable[..., Any], timeout: float) -> str:
    _strict_official_url(url, label="certificate URL")
    with opener(url, timeout=timeout) as response:
        payload = response.read()
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BeaconVerificationError("NIST certificate response is not ASCII PEM") from exc


def fetch_beacon_receipt(
    *,
    protocol: object,
    anchor_granted_at_utc: str,
    fetched_at_utc: str,
    timeout: float = 20.0,
    openssl_bin: str = "openssl",
    opener: Callable[..., Any] = urlopen,
) -> dict[str, Any]:
    """Fetch the deterministic first pulse pair from official HTTPS endpoints."""

    frozen = validate_protocol(protocol)
    anchor = _parse_utc(anchor_granted_at_utc, label="anchor_granted_at_utc")[0]
    cutoff = anchor + timedelta(seconds=frozen["external_beacon_delay_seconds"])
    cutoff_ms = int(cutoff.timestamp() * 1000) + 1
    query_url = f"{_SOURCE}/pulse/time/next/{cutoff_ms}"
    current = _fetch_json(query_url, opener=opener, timeout=timeout)
    exact_current = _fetch_json(current["uri"], opener=opener, timeout=timeout)
    if current != exact_current:
        raise BeaconVerificationError("selection query and exact pulse endpoint disagree")
    previous_uri = next(
        (item["uri"] for item in current.get("listValues", []) if item.get("type") == "previous"),
        None,
    )
    if previous_uri is None:
        raise BeaconVerificationError("selected pulse has no previous pulse URI")
    previous = _fetch_json(previous_uri, opener=opener, timeout=timeout)
    current_cert_url = f"{_SOURCE}/certificate/{current['certificateId']}"
    previous_cert_url = f"{_SOURCE}/certificate/{previous['certificateId']}"
    return build_beacon_receipt(
        protocol=frozen,
        anchor_granted_at_utc=anchor_granted_at_utc,
        current_pulse=current,
        previous_pulse=previous,
        current_certificate_pem=_fetch_text(current_cert_url, opener=opener, timeout=timeout),
        previous_certificate_pem=_fetch_text(previous_cert_url, opener=opener, timeout=timeout),
        fetched_at_utc=fetched_at_utc,
        openssl_bin=openssl_bin,
    )


def write_beacon_receipt_once(
    path: str | Path,
    receipt: object,
    *,
    protocol: object,
    openssl_bin: str = "openssl",
) -> Path:
    validated = validate_beacon_receipt(receipt, protocol=protocol, openssl_bin=openssl_bin)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as handle:
            handle.write(canonical_json_bytes(validated) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"beacon receipt already exists: {target}") from None
    return target


__all__ = [
    "RECEIPT_SCHEMA",
    "BeaconVerificationError",
    "build_beacon_receipt",
    "fetch_beacon_receipt",
    "validate_beacon_receipt",
    "write_beacon_receipt_once",
]
