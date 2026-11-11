"""Fail-closed G06 exact independent DEV byte-rebuild custody.

G06 derives every expected input root from one exact canonical upstream byte
bundle.  It accepts no caller-authored root summaries or independence flags.
Two independently pinned rebuild-host keys attest typed execution inventories;
a separate validation key countersigns the exact derived pair audit.

Success is research evidence only.  This module has no candidate, holdout,
release, composer-allowlist, or submission authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime, timezone
import re
from typing import Any, Mapping, Sequence

from .canonical import canonical_sha256
from .envelope import verify_envelope
from .exact_gate_v2 import (
    ExactGateV2Error,
    decode_byte_evidence as _decode_v2_byte_evidence,
    encode_byte_evidence as _encode_v2_byte_evidence,
    strict_canonical_json,
    validate_ed25519_public_key,
    validate_ed25519_signature_encoding,
)


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
G06_GATE_ID = "G06_DEV_BYTE_REBUILD"
HOST_RECEIPT_SCHEMA = "evaluation_v5_1_g06_rebuild_host_receipt_v2"
PAIR_AUDIT_SCHEMA = "evaluation_v5_1_g06_rebuild_pair_audit_v2"
VALIDATION_COUNTERSIGNATURE_SCHEMA = (
    "evaluation_v5_1_g06_rebuild_validation_countersignature_v2"
)
UPSTREAM_DEPENDENCY_BUNDLE_SCHEMA = (
    "evaluation_v5_1_g06_upstream_dependency_bundle_v1"
)
EXECUTION_POLICY_SCHEMA = "evaluation_v5_1_g06_execution_policy_v1"
PLATFORM_INVENTORY_SCHEMA = "evaluation_v5_1_g06_platform_inventory_v1"
WORKSPACE_INVENTORY_SCHEMA = "evaluation_v5_1_g06_workspace_inventory_v2"
UPSTREAM_DEPENDENCY_BUNDLE_MEDIA_TYPE = (
    "application/vnd.evaluation-v5-1.g06-upstream-dependency-bundle+json"
)
G06_DECISION = "G06_BYTE_REBUILD_VERIFIED_RESEARCH_ONLY"

INPUT_NAMES = (
    "campaign_root",
    "g05_result",
    "development_evidence",
    "frozen_source",
    "source_manifest",
    "container",
    "runtime",
    "toolchain",
    "executable",
    "input_dataset",
    "fit_spec",
)
OUTPUT_NAMES = (
    "result_core",
    "candidate_score_table",
    "selection_receipt",
    "prediction_transcript",
    "mci_manifest",
    "comparator_manifest",
    "stdout",
    "stderr",
)

_INPUT_PATHS = {name: f"/g06/input/{name}" for name in INPUT_NAMES}
_OUTPUT_PATHS = {name: f"/g06/output/{name}" for name in OUTPUT_NAMES}
_BINARY_PATHS = {
    "runtime": "/opt/g06/bin/runtime",
    "toolchain": "/opt/g06/bin/toolchain",
    "executable": "/opt/g06/bin/rebuild",
}
_BINARY_NAMES = tuple(_BINARY_PATHS)
_ENVELOPE_FIELDS = frozenset(
    {
        "schema",
        "artifact_schema",
        "payload",
        "payload_sha256",
        "signer_key_fingerprint_sha256",
        "signature_ed25519_base64",
    }
)
_UPSTREAM_FIELDS = frozenset(
    {"schema", "protocol_id", "gate_id", "evaluation_id", "inputs", "execution_policy"}
)
_POLICY_FIELDS = frozenset({"schema", "argv", "env_allowlist", "max_duration_us"})
_ENV_ALLOW_FIELDS = frozenset({"name", "allowed_values"})
_HOST_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "gate_id",
        "evaluation_id",
        "attestor_key_id",
        "custody",
        "platform_inventory",
        "binary_inventory",
        "invocation",
        "chronology",
        "workspace_pre_inventory",
        "workspace_post_inventory",
        "execution",
        "inputs",
        "input_inventory",
        "outputs",
        "output_inventory",
    }
)
_CUSTODY_FIELDS = frozenset(
    {"principal_id", "custodian_id", "host_instance_id", "execution_nonce"}
)
_PLATFORM_FIELDS = frozenset(
    {
        "schema",
        "os",
        "arch",
        "container_image_sha256",
        "runtime_sha256",
        "toolchain_sha256",
        "executable_sha256",
        "network_mode",
        "rootfs_read_only",
    }
)
_BINARY_FIELDS = frozenset(
    {"binary_id", "path", "sha256", "decoded_length", "mode"}
)
_INVOCATION_FIELDS = frozenset({"binary_path", "argv", "env"})
_ENV_FIELDS = frozenset({"name", "value"})
_CHRONOLOGY_FIELDS = frozenset({"started_at_utc", "ended_at_utc"})
_WORKSPACE_FIELDS = frozenset({"schema", "entries"})
_EXECUTION_FIELDS = frozenset(
    {"attempt_index", "retry_count", "intervention_count", "exit_code"}
)
_ARTIFACT_FIELDS = frozenset(
    {"artifact_id", "path", "sha256", "decoded_length", "media_type"}
)
_PAIR_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "gate_id",
        "evaluation_id",
        "upstream_dependency_bundle_sha256",
        "upstream_dependency_bundle_decoded_length",
        "host_receipt_envelope_sha256s",
        "host_key_ids",
        "host_principal_ids",
        "host_custodian_ids",
        "host_instance_ids",
        "execution_nonces",
        "input_roots",
        "output_roots",
        "platform_inventory_sha256s",
        "binary_inventory_sha256s",
        "invocation_sha256s",
        "input_inventory_sha256s",
        "output_inventory_sha256s",
        "workspace_pre_inventory_sha256s",
        "workspace_post_inventory_sha256s",
        "chronologies",
        "decision",
        "authority",
        "candidate_development_authorized",
        "sealed_holdout_access_authorized",
        "release_authorized",
        "submission_authorized",
    }
)
_COUNTERSIGNATURE_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "gate_id",
        "validator_key_id",
        "pair_audit_sha256",
        "decision",
        "authority",
        "candidate_development_authorized",
        "sealed_holdout_access_authorized",
        "release_authorized",
        "submission_authorized",
    }
)
_AUTHORITY_KEYS = frozenset(
    {
        "authority",
        "candidate_development_authorized",
        "sealed_holdout_access_authorized",
        "sealed_holdout_access",
        "holdout_access",
        "holdout_access_authorized",
        "release_authorized",
        "submission_authorized",
        "production_submission_authorized",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_MAX_ARG_COUNT = 32
_MAX_ARG_BYTES = 4096
_MAX_ENV_COUNT = 32
_MAX_ENV_VALUE_BYTES = 1024


class RebuildCustodyError(ValueError):
    """G06 raw evidence, custody, or signature verification failed."""


def encode_byte_evidence(raw: bytes, *, media_type: str) -> dict[str, object]:
    """Use the bounded exact-gate-v2 byte representation."""

    try:
        return _encode_v2_byte_evidence(raw, media_type=media_type)
    except ExactGateV2Error as exc:
        raise RebuildCustodyError(str(exc)) from exc


def decode_byte_evidence(
    value: object, *, expected_media_type: str | None = None
) -> bytes:
    """Decode bounded bytes and recompute length, base64, media type, and hash."""

    try:
        return _decode_v2_byte_evidence(value, expected_media_type=expected_media_type)
    except ExactGateV2Error as exc:
        raise RebuildCustodyError(str(exc)) from exc


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise RebuildCustodyError(f"{label} fields are not exact")
    return value


def _sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise RebuildCustodyError(f"{label} must be lowercase SHA-256 hex")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise RebuildCustodyError(f"{label} must be a bounded canonical identifier")
    return value


def _bounded_text(value: object, label: str, *, max_bytes: int) -> str:
    if type(value) is not str or not value or value.strip() != value or "\x00" in value:
        raise RebuildCustodyError(f"{label} must be non-empty trimmed text without NUL")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise RebuildCustodyError(f"{label} is not valid UTF-8 text") from exc
    if length > max_bytes:
        raise RebuildCustodyError(f"{label} exceeds its frozen byte bound")
    return value


def _uint(value: object, label: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise RebuildCustodyError(f"{label} must be a bounded non-negative integer")
    return value


def _utc(value: object, label: str) -> datetime:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise RebuildCustodyError(f"{label} must be canonical microsecond UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise RebuildCustodyError(f"{label} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise RebuildCustodyError(f"{label} is not canonical microsecond UTC")
    return parsed


def _elapsed_us(start: datetime, end: datetime) -> int:
    delta = end - start
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _reject_private_or_authority(value: object, *, path: str = "$") -> None:
    if type(value) is dict:
        for key, child in value.items():
            lowered = key.lower()
            if (
                ("private" in lowered and "key" in lowered)
                or lowered in {"secret", "secret_key", "signing_seed", "private_seed"}
            ):
                raise RebuildCustodyError(f"{path}.{key} contains private material")
            if key in _AUTHORITY_KEYS and child is not False:
                raise RebuildCustodyError(f"{path}.{key} claims forbidden authority")
            if type(child) is bool and child and (
                lowered in {"pass", "passed", "success", "verified"}
                or lowered.endswith("_pass")
            ):
                raise RebuildCustodyError(f"{path}.{key} is a caller pass flag")
            _reject_private_or_authority(child, path=f"{path}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _reject_private_or_authority(child, path=f"{path}[{index}]")


def _strict_key_id(public_key: bytes, label: str) -> str:
    try:
        return validate_ed25519_public_key(public_key)
    except ExactGateV2Error as exc:
        raise RebuildCustodyError(f"{label} is not a strict Ed25519 public key: {exc}") from exc


def _signature_bytes(envelope: object) -> bytes:
    raw = _exact(envelope, _ENVELOPE_FIELDS, "signed envelope")
    value = raw["signature_ed25519_base64"]
    if type(value) is not str:
        raise RebuildCustodyError("signature must be canonical base64")
    try:
        signature = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RebuildCustodyError("signature must be canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != value:
        raise RebuildCustodyError("signature must encode exactly 64 bytes")
    return signature


def _strict_verify_envelope(
    envelope: object, *, schema: str, public_key: bytes, label: str
) -> tuple[dict[str, Any], str]:
    # These two shared v2 validators must run before envelope.py reaches its
    # Ed25519 verification call.  This rejects noncanonical/torsion/mixed-order
    # A and R encodings and S >= L independently of the crypto backend.
    key_id = _strict_key_id(public_key, f"{label} public key")
    signature = _signature_bytes(envelope)
    try:
        validate_ed25519_signature_encoding(signature)
    except ExactGateV2Error as exc:
        raise RebuildCustodyError(f"{label} signature encoding is invalid: {exc}") from exc
    try:
        payload = verify_envelope(
            envelope,
            expected_artifact_schema=schema,
            pinned_public_key_bytes=public_key,
        )
    except ValueError as exc:
        raise RebuildCustodyError(f"{label} signature verification failed: {exc}") from exc
    return payload, key_id


def _byte_map(
    value: object, names: tuple[str, ...], label: str
) -> tuple[dict[str, Any], dict[str, str]]:
    if type(value) is not dict or set(value) != set(names):
        raise RebuildCustodyError(f"{label} must contain every exact byte artifact once")
    checked: dict[str, Any] = {}
    roots: dict[str, str] = {}
    for name in names:
        raw = decode_byte_evidence(value[name])
        if b"-----BEGIN" in raw and b"PRIVATE KEY-----" in raw:
            raise RebuildCustodyError(f"{label}.{name} contains private material")
        checked[name] = value[name]
        roots[name] = _sha(value[name]["sha256"], f"{label}.{name}.sha256")
    return checked, roots


def _root_map(value: object, names: tuple[str, ...], label: str) -> dict[str, str]:
    if type(value) is not dict or set(value) != set(names):
        raise RebuildCustodyError(f"{label} must contain every exact root once")
    return {name: _sha(value[name], f"{label}.{name}") for name in names}


def _argv(value: object, label: str) -> list[str]:
    if type(value) is not list or not value or len(value) > _MAX_ARG_COUNT:
        raise RebuildCustodyError(f"{label} must be a non-empty bounded argv list")
    result = [
        _bounded_text(item, f"{label}[{index}]", max_bytes=_MAX_ARG_BYTES)
        for index, item in enumerate(value)
    ]
    if sum(len(item.encode("utf-8")) for item in result) > _MAX_ARG_BYTES:
        raise RebuildCustodyError(f"{label} exceeds its aggregate byte bound")
    return result


def _env_allowlist(value: object) -> list[dict[str, Any]]:
    if type(value) is not list or not value or len(value) > _MAX_ENV_COUNT:
        raise RebuildCustodyError("env allowlist must be non-empty and bounded")
    result: list[dict[str, Any]] = []
    prior = ""
    for index, item in enumerate(value):
        row = _exact(item, _ENV_ALLOW_FIELDS, f"env_allowlist[{index}]")
        name = row["name"]
        if type(name) is not str or _ENV_NAME_RE.fullmatch(name) is None or name <= prior:
            raise RebuildCustodyError("env allowlist names must be unique and sorted")
        allowed = row["allowed_values"]
        if type(allowed) is not list or not allowed or len(allowed) > 16:
            raise RebuildCustodyError("env allowed_values must be non-empty and bounded")
        values = [
            _bounded_text(entry, f"env_allowlist[{index}].allowed_values", max_bytes=_MAX_ENV_VALUE_BYTES)
            for entry in allowed
        ]
        if values != sorted(set(values)):
            raise RebuildCustodyError("env allowed_values must be unique and sorted")
        result.append({"name": name, "allowed_values": values})
        prior = name
    return result


def _execution_policy(value: object) -> dict[str, Any]:
    raw = _exact(value, _POLICY_FIELDS, "execution policy")
    if raw["schema"] != EXECUTION_POLICY_SCHEMA:
        raise RebuildCustodyError("execution policy schema mismatch")
    maximum = _uint(raw["max_duration_us"], "max_duration_us", maximum=86_400_000_000)
    if maximum == 0:
        raise RebuildCustodyError("max_duration_us must be positive")
    return {
        "schema": EXECUTION_POLICY_SCHEMA,
        "argv": _argv(raw["argv"], "execution policy argv"),
        "env_allowlist": _env_allowlist(raw["env_allowlist"]),
        "max_duration_us": maximum,
    }


def _upstream_bundle(value: object) -> dict[str, Any]:
    raw_bytes = decode_byte_evidence(
        value, expected_media_type=UPSTREAM_DEPENDENCY_BUNDLE_MEDIA_TYPE
    )
    try:
        parsed = strict_canonical_json(raw_bytes, label="G06 upstream dependency bundle")
    except ExactGateV2Error as exc:
        raise RebuildCustodyError(str(exc)) from exc
    raw = _exact(parsed, _UPSTREAM_FIELDS, "upstream dependency bundle")
    _reject_private_or_authority(raw)
    if (
        raw["schema"] != UPSTREAM_DEPENDENCY_BUNDLE_SCHEMA
        or raw["protocol_id"] != PROTOCOL_ID
        or raw["gate_id"] != G06_GATE_ID
    ):
        raise RebuildCustodyError("upstream dependency bundle identity mismatch")
    evaluation_id = _identifier(raw["evaluation_id"], "upstream evaluation_id")
    inputs, roots = _byte_map(raw["inputs"], INPUT_NAMES, "upstream inputs")
    return {
        "evaluation_id": evaluation_id,
        "inputs": inputs,
        "input_roots": roots,
        "execution_policy": _execution_policy(raw["execution_policy"]),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "decoded_length": len(raw_bytes),
    }


def _artifact_inventory(
    value: object,
    *,
    names: tuple[str, ...],
    paths: Mapping[str, str],
    wrappers: Mapping[str, Any],
    label: str,
) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) != len(names):
        raise RebuildCustodyError(f"{label} cardinality mismatch")
    result: list[dict[str, Any]] = []
    for index, name in enumerate(names):
        row = _exact(value[index], _ARTIFACT_FIELDS, f"{label}[{index}]")
        length = _uint(row["decoded_length"], f"{label}[{index}].decoded_length")
        expected = wrappers[name]
        if (
            row["artifact_id"] != name
            or row["path"] != paths[name]
            or _sha(row["sha256"], f"{label}[{index}].sha256") != expected["sha256"]
            or length != expected["decoded_length"]
            or row["media_type"] != expected["media_type"]
        ):
            raise RebuildCustodyError(f"{label}[{index}] does not match exact bytes")
        result.append(dict(row))
    return result


def _binary_inventory(
    value: object, inputs: Mapping[str, Any]
) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) != len(_BINARY_NAMES):
        raise RebuildCustodyError("binary inventory cardinality mismatch")
    result: list[dict[str, Any]] = []
    for index, name in enumerate(_BINARY_NAMES):
        row = _exact(value[index], _BINARY_FIELDS, f"binary_inventory[{index}]")
        length = _uint(row["decoded_length"], f"binary_inventory[{index}].decoded_length")
        if (
            row["binary_id"] != name
            or row["path"] != _BINARY_PATHS[name]
            or _sha(row["sha256"], f"binary_inventory[{index}].sha256") != inputs[name]["sha256"]
            or length != inputs[name]["decoded_length"]
            or row["mode"] != "0555"
        ):
            raise RebuildCustodyError("binary inventory does not bind the frozen binaries")
        result.append(dict(row))
    return result


def _platform_inventory(
    value: object, inputs: Mapping[str, Any]
) -> dict[str, Any]:
    raw = _exact(value, _PLATFORM_FIELDS, "platform inventory")
    if (
        raw["schema"] != PLATFORM_INVENTORY_SCHEMA
        or raw["os"] != "linux"
        or raw["arch"] != "amd64"
        or raw["container_image_sha256"] != inputs["container"]["sha256"]
        or raw["runtime_sha256"] != inputs["runtime"]["sha256"]
        or raw["toolchain_sha256"] != inputs["toolchain"]["sha256"]
        or raw["executable_sha256"] != inputs["executable"]["sha256"]
        or raw["network_mode"] != "none"
        or type(raw["rootfs_read_only"]) is not bool
        or raw["rootfs_read_only"] is not True
    ):
        raise RebuildCustodyError("platform inventory is not exact isolated Linux/amd64")
    return dict(raw)


def _invocation(value: object, policy: Mapping[str, Any]) -> dict[str, Any]:
    raw = _exact(value, _INVOCATION_FIELDS, "invocation")
    argv = _argv(raw["argv"], "invocation argv")
    if raw["binary_path"] != _BINARY_PATHS["executable"] or argv != policy["argv"]:
        raise RebuildCustodyError("invocation does not match the frozen argv")
    env = raw["env"]
    allowlist = policy["env_allowlist"]
    if type(env) is not list or len(env) != len(allowlist):
        raise RebuildCustodyError("invocation env does not match the frozen allowlist")
    checked: list[dict[str, str]] = []
    for index, allowed in enumerate(allowlist):
        row = _exact(env[index], _ENV_FIELDS, f"invocation.env[{index}]")
        value_text = _bounded_text(
            row["value"], f"invocation.env[{index}].value", max_bytes=_MAX_ENV_VALUE_BYTES
        )
        if row["name"] != allowed["name"] or value_text not in allowed["allowed_values"]:
            raise RebuildCustodyError("invocation env is outside the frozen allowlist")
        checked.append({"name": row["name"], "value": value_text})
    return {"binary_path": raw["binary_path"], "argv": argv, "env": checked}


def _workspace_inventory(
    value: object, *, expected_entries: Sequence[Mapping[str, Any]], label: str
) -> dict[str, Any]:
    raw = _exact(value, _WORKSPACE_FIELDS, label)
    if raw["schema"] != WORKSPACE_INVENTORY_SCHEMA or raw["entries"] != list(expected_entries):
        raise RebuildCustodyError(f"{label} does not prove exact clean workspace custody")
    return {"schema": WORKSPACE_INVENTORY_SCHEMA, "entries": list(raw["entries"])}


def _execution(value: object) -> dict[str, int]:
    raw = _exact(value, _EXECUTION_FIELDS, "execution")
    checked = {
        field: _uint(raw[field], f"execution.{field}")
        for field in _EXECUTION_FIELDS
    }
    if checked != {
        "attempt_index": 0,
        "retry_count": 0,
        "intervention_count": 0,
        "exit_code": 0,
    }:
        raise RebuildCustodyError(
            "rebuild must be first-attempt, unretried, unintervened, and successful"
        )
    return checked


def _host_receipt(
    envelope: object,
    *,
    public_key: bytes,
    expected_key_id: str,
    upstream: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    payload, verified_key_id = _strict_verify_envelope(
        envelope, schema=HOST_RECEIPT_SCHEMA, public_key=public_key, label="host receipt"
    )
    if verified_key_id != expected_key_id:
        raise RebuildCustodyError("derived host key identity changed during verification")
    raw = _exact(payload, _HOST_FIELDS, "host receipt")
    _reject_private_or_authority(raw)
    if (
        raw["schema"] != HOST_RECEIPT_SCHEMA
        or raw["protocol_id"] != PROTOCOL_ID
        or raw["gate_id"] != G06_GATE_ID
        or raw["evaluation_id"] != upstream["evaluation_id"]
        or raw["attestor_key_id"] != expected_key_id
    ):
        raise RebuildCustodyError("host receipt identity or derived key id mismatch")

    custody = _exact(raw["custody"], _CUSTODY_FIELDS, "host custody")
    checked_custody = {
        field: _identifier(custody[field], f"custody.{field}") for field in _CUSTODY_FIELDS
    }
    inputs, input_roots = _byte_map(raw["inputs"], INPUT_NAMES, "host inputs")
    if inputs != upstream["inputs"] or input_roots != upstream["input_roots"]:
        raise RebuildCustodyError("host inputs differ from exact upstream dependency bytes")
    input_inventory = _artifact_inventory(
        raw["input_inventory"],
        names=INPUT_NAMES,
        paths=_INPUT_PATHS,
        wrappers=inputs,
        label="input inventory",
    )
    platform = _platform_inventory(raw["platform_inventory"], inputs)
    binaries = _binary_inventory(raw["binary_inventory"], inputs)
    invocation = _invocation(raw["invocation"], upstream["execution_policy"])

    chronology = _exact(raw["chronology"], _CHRONOLOGY_FIELDS, "chronology")
    start = _utc(chronology["started_at_utc"], "chronology.started_at_utc")
    end = _utc(chronology["ended_at_utc"], "chronology.ended_at_utc")
    duration_us = _elapsed_us(start, end)
    if duration_us <= 0 or duration_us > upstream["execution_policy"]["max_duration_us"]:
        raise RebuildCustodyError("rebuild chronology is non-forward or exceeds its bound")

    outputs, output_roots = _byte_map(raw["outputs"], OUTPUT_NAMES, "host outputs")
    output_inventory = _artifact_inventory(
        raw["output_inventory"],
        names=OUTPUT_NAMES,
        paths=_OUTPUT_PATHS,
        wrappers=outputs,
        label="output inventory",
    )
    workspace_pre = _workspace_inventory(
        raw["workspace_pre_inventory"], expected_entries=[], label="workspace pre inventory"
    )
    workspace_post = _workspace_inventory(
        raw["workspace_post_inventory"],
        expected_entries=output_inventory,
        label="workspace post inventory",
    )
    execution = _execution(raw["execution"])
    checked = dict(raw)
    checked.update(
        {
            "_custody": checked_custody,
            "_input_roots": input_roots,
            "_output_roots": output_roots,
            "_platform_root": canonical_sha256(platform),
            "_binary_root": canonical_sha256(binaries),
            "_invocation_root": canonical_sha256(invocation),
            "_input_inventory_root": canonical_sha256(input_inventory),
            "_output_inventory_root": canonical_sha256(output_inventory),
            "_workspace_pre_root": canonical_sha256(workspace_pre),
            "_workspace_post_root": canonical_sha256(workspace_post),
            "_execution": execution,
        }
    )
    return checked, canonical_sha256(envelope)


def _pinned_host_keys(public_keys: Sequence[bytes]) -> dict[str, bytes]:
    if type(public_keys) not in {list, tuple} or len(public_keys) != 2:
        raise RebuildCustodyError("exactly two pinned rebuild-host public keys are required")
    result: dict[str, bytes] = {}
    for index, public_key in enumerate(public_keys):
        key_id = _strict_key_id(public_key, f"host key {index}")
        if key_id in result:
            raise RebuildCustodyError("rebuild-host public keys must be distinct")
        result[key_id] = public_key
    return result


def derive_rebuild_custody_audit(
    *,
    host_receipt_envelopes: Sequence[object],
    host_attestor_public_keys: Sequence[bytes],
    upstream_dependency_bundle: object,
) -> dict[str, Any]:
    """Derive a G06 pair audit from exact raw bytes and typed custody records."""

    upstream = _upstream_bundle(upstream_dependency_bundle)
    pinned = _pinned_host_keys(host_attestor_public_keys)
    if type(host_receipt_envelopes) not in {list, tuple} or len(host_receipt_envelopes) != 2:
        raise RebuildCustodyError("exactly two host receipt envelopes are required")

    checked: list[tuple[dict[str, Any], str]] = []
    seen: set[str] = set()
    for envelope in host_receipt_envelopes:
        if type(envelope) is not dict or type(envelope.get("payload")) is not dict:
            raise RebuildCustodyError("host receipt envelope is malformed")
        untrusted_key_id = envelope["payload"].get("attestor_key_id")
        if (
            type(untrusted_key_id) is not str
            or untrusted_key_id not in pinned
            or untrusted_key_id in seen
        ):
            raise RebuildCustodyError("each derived pinned host key id must be used exactly once")
        seen.add(untrusted_key_id)
        checked.append(
            _host_receipt(
                envelope,
                public_key=pinned[untrusted_key_id],
                expected_key_id=untrusted_key_id,
                upstream=upstream,
            )
        )
    if seen != set(pinned):
        raise RebuildCustodyError("both pinned host keys must sign exactly one receipt")

    receipts = [item[0] for item in checked]
    for field in ("principal_id", "custodian_id", "host_instance_id", "execution_nonce"):
        if len({receipt["_custody"][field] for receipt in receipts}) != 2:
            raise RebuildCustodyError(f"rebuild independence requires distinct {field}s")
    principals = {receipt["_custody"]["principal_id"] for receipt in receipts}
    custodians = {receipt["_custody"]["custodian_id"] for receipt in receipts}
    if principals & custodians:
        raise RebuildCustodyError("principal and custodian identities must not alias")
    if receipts[0]["inputs"] != receipts[1]["inputs"]:
        raise RebuildCustodyError("independent hosts did not consume identical upstream bytes")
    if receipts[0]["outputs"] != receipts[1]["outputs"]:
        raise RebuildCustodyError("independent hosts did not produce byte-identical outputs")
    if receipts[0]["platform_inventory"] != receipts[1]["platform_inventory"]:
        raise RebuildCustodyError("independent hosts used different frozen platform inventories")
    if receipts[0]["binary_inventory"] != receipts[1]["binary_inventory"]:
        raise RebuildCustodyError("independent hosts used different frozen binary inventories")
    if receipts[0]["invocation"] != receipts[1]["invocation"]:
        raise RebuildCustodyError("independent hosts used different invocations")

    ordered = sorted(
        zip(receipts, [item[1] for item in checked]), key=lambda item: item[0]["attestor_key_id"]
    )
    receipts = [item[0] for item in ordered]
    envelope_roots = [item[1] for item in ordered]
    return {
        "schema": PAIR_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "gate_id": G06_GATE_ID,
        "evaluation_id": upstream["evaluation_id"],
        "upstream_dependency_bundle_sha256": upstream["sha256"],
        "upstream_dependency_bundle_decoded_length": upstream["decoded_length"],
        "host_receipt_envelope_sha256s": envelope_roots,
        "host_key_ids": [receipt["attestor_key_id"] for receipt in receipts],
        "host_principal_ids": [receipt["_custody"]["principal_id"] for receipt in receipts],
        "host_custodian_ids": [receipt["_custody"]["custodian_id"] for receipt in receipts],
        "host_instance_ids": [receipt["_custody"]["host_instance_id"] for receipt in receipts],
        "execution_nonces": [receipt["_custody"]["execution_nonce"] for receipt in receipts],
        "input_roots": dict(upstream["input_roots"]),
        "output_roots": dict(receipts[0]["_output_roots"]),
        "platform_inventory_sha256s": [receipt["_platform_root"] for receipt in receipts],
        "binary_inventory_sha256s": [receipt["_binary_root"] for receipt in receipts],
        "invocation_sha256s": [receipt["_invocation_root"] for receipt in receipts],
        "input_inventory_sha256s": [receipt["_input_inventory_root"] for receipt in receipts],
        "output_inventory_sha256s": [receipt["_output_inventory_root"] for receipt in receipts],
        "workspace_pre_inventory_sha256s": [receipt["_workspace_pre_root"] for receipt in receipts],
        "workspace_post_inventory_sha256s": [receipt["_workspace_post_root"] for receipt in receipts],
        "chronologies": [dict(receipt["chronology"]) for receipt in receipts],
        "decision": G06_DECISION,
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "release_authorized": False,
        "submission_authorized": False,
    }


def derive_validation_countersignature_payload(
    pair_audit: object, *, validation_authority_public_key: bytes
) -> dict[str, Any]:
    """Return the exact research-only payload the validator must sign."""

    audit = _exact(pair_audit, _PAIR_FIELDS, "pair audit")
    if (
        audit["schema"] != PAIR_AUDIT_SCHEMA
        or audit["protocol_id"] != PROTOCOL_ID
        or audit["gate_id"] != G06_GATE_ID
        or audit["decision"] != G06_DECISION
    ):
        raise RebuildCustodyError("pair audit identity mismatch")
    _reject_private_or_authority(audit)
    _identifier(audit["evaluation_id"], "pair audit evaluation_id")
    _sha(
        audit["upstream_dependency_bundle_sha256"],
        "pair audit upstream dependency bundle sha256",
    )
    _uint(
        audit["upstream_dependency_bundle_decoded_length"],
        "pair audit upstream dependency bundle decoded length",
    )
    _root_map(audit["input_roots"], INPUT_NAMES, "pair audit input roots")
    _root_map(audit["output_roots"], OUTPUT_NAMES, "pair audit output roots")
    for field in (
        "host_receipt_envelope_sha256s",
        "platform_inventory_sha256s",
        "binary_inventory_sha256s",
        "invocation_sha256s",
        "input_inventory_sha256s",
        "output_inventory_sha256s",
        "workspace_pre_inventory_sha256s",
        "workspace_post_inventory_sha256s",
    ):
        values = audit[field]
        if type(values) is not list or len(values) != 2:
            raise RebuildCustodyError(f"pair audit {field} must contain exactly two roots")
        for index, value in enumerate(values):
            _sha(value, f"pair audit {field}[{index}]")
    key_ids = audit["host_key_ids"]
    if (
        type(key_ids) is not list
        or len(key_ids) != 2
        or key_ids != sorted(set(key_ids))
        or any(
            type(item) is not str
            or not item.startswith("ed25519-sha256:")
            or _SHA256_RE.fullmatch(item[15:]) is None
            for item in key_ids
        )
    ):
        raise RebuildCustodyError("pair audit host key ids are not exact and distinct")
    for field in (
        "host_principal_ids",
        "host_custodian_ids",
        "host_instance_ids",
        "execution_nonces",
    ):
        values = audit[field]
        if (
            type(values) is not list
            or len(values) != 2
            or len(set(values)) != 2
        ):
            raise RebuildCustodyError(f"pair audit {field} must contain two distinct identities")
        for index, value in enumerate(values):
            _identifier(value, f"pair audit {field}[{index}]")
    chronologies = audit["chronologies"]
    if type(chronologies) is not list or len(chronologies) != 2:
        raise RebuildCustodyError("pair audit must contain exactly two chronologies")
    for index, chronology_value in enumerate(chronologies):
        chronology = _exact(
            chronology_value, _CHRONOLOGY_FIELDS, f"pair audit chronology[{index}]"
        )
        if _utc(
            chronology["ended_at_utc"], f"pair audit chronology[{index}].ended"
        ) <= _utc(
            chronology["started_at_utc"], f"pair audit chronology[{index}].started"
        ):
            raise RebuildCustodyError("pair audit chronology is not forward")
    return {
        "schema": VALIDATION_COUNTERSIGNATURE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "gate_id": G06_GATE_ID,
        "validator_key_id": _strict_key_id(
            validation_authority_public_key, "validation authority key"
        ),
        "pair_audit_sha256": canonical_sha256(audit),
        "decision": G06_DECISION,
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "release_authorized": False,
        "submission_authorized": False,
    }


def verify_rebuild_custody(
    *,
    host_receipt_envelopes: Sequence[object],
    host_attestor_public_keys: Sequence[bytes],
    upstream_dependency_bundle: object,
    validation_authority_envelope: object,
    validation_authority_public_key: bytes,
) -> dict[str, Any]:
    """Verify exact G06 evidence and the validation authority countersignature."""

    validator_key_id = _strict_key_id(
        validation_authority_public_key, "validation authority key"
    )
    host_key_ids = {
        _strict_key_id(key, f"host key {index}")
        for index, key in enumerate(host_attestor_public_keys)
    }
    if validator_key_id in host_key_ids:
        raise RebuildCustodyError("validation key must be distinct from both host keys")
    audit = derive_rebuild_custody_audit(
        host_receipt_envelopes=host_receipt_envelopes,
        host_attestor_public_keys=host_attestor_public_keys,
        upstream_dependency_bundle=upstream_dependency_bundle,
    )
    signed, verified_validator_key_id = _strict_verify_envelope(
        validation_authority_envelope,
        schema=VALIDATION_COUNTERSIGNATURE_SCHEMA,
        public_key=validation_authority_public_key,
        label="validation countersignature",
    )
    if verified_validator_key_id != validator_key_id:
        raise RebuildCustodyError("validation key identity changed during verification")
    signed = _exact(signed, _COUNTERSIGNATURE_FIELDS, "validation countersignature")
    expected = derive_validation_countersignature_payload(
        audit, validation_authority_public_key=validation_authority_public_key
    )
    if signed != expected:
        raise RebuildCustodyError("validator did not countersign the exact G06 pair audit")
    return audit


audit_rebuild_custody = verify_rebuild_custody
verify_g06_rebuild_custody = verify_rebuild_custody
derive_g06_pair_audit = derive_rebuild_custody_audit


__all__ = [
    "EXECUTION_POLICY_SCHEMA",
    "G06_DECISION",
    "G06_GATE_ID",
    "HOST_RECEIPT_SCHEMA",
    "INPUT_NAMES",
    "OUTPUT_NAMES",
    "PAIR_AUDIT_SCHEMA",
    "PLATFORM_INVENTORY_SCHEMA",
    "PROTOCOL_ID",
    "RebuildCustodyError",
    "UPSTREAM_DEPENDENCY_BUNDLE_MEDIA_TYPE",
    "UPSTREAM_DEPENDENCY_BUNDLE_SCHEMA",
    "VALIDATION_COUNTERSIGNATURE_SCHEMA",
    "WORKSPACE_INVENTORY_SCHEMA",
    "audit_rebuild_custody",
    "decode_byte_evidence",
    "derive_g06_pair_audit",
    "derive_rebuild_custody_audit",
    "derive_validation_countersignature_payload",
    "encode_byte_evidence",
    "verify_g06_rebuild_custody",
    "verify_rebuild_custody",
]
