"""Exact-gate v2 wire, closure, and replay primitives.

This is the safe migration foundation, not an authority service.  The hermetic
verifier allowlist is deliberately empty, so no G00-G15 bundle can yet return a
verified pass.  Later integration must resolve trust from raw G00 evidence and
invoke a content-addressed verifier runtime before enabling any gate.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sqlite3
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
FINAL_BUNDLE_SCHEMA = "ptcg.exact_gate.bundle/v2"
AUTHORITY_ENVELOPE_SCHEMA = "ptcg.exact_gate.authority-envelope/v2"
VALIDATOR_ENVELOPE_SCHEMA = "ptcg.exact_gate.validator-envelope/v2"
AUTHORITY_PAYLOAD_SCHEMA = "ptcg.exact_gate.authority/v2"
VALIDATOR_PAYLOAD_SCHEMA = "ptcg.exact_gate.validator/v2"
EVIDENCE_MANIFEST_SCHEMA = "ptcg.exact_gate.evidence-manifest/v2"

AUTHORITY_MEDIA_TYPE = "application/vnd.ptcg.exact-gate-authority+json"
VALIDATOR_MEDIA_TYPE = "application/vnd.ptcg.exact-gate-validator+json"
AUTHORITY_PAYLOAD_MEDIA_TYPE = "application/vnd.ptcg.exact-gate-authority-payload+json"
VALIDATOR_PAYLOAD_MEDIA_TYPE = "application/vnd.ptcg.exact-gate-validator-payload+json"
MANIFEST_MEDIA_TYPE = "application/vnd.ptcg.exact-gate-evidence-manifest+json"

AUTHORITY_DOMAIN = b"PTCG/EXACT_GATE/AUTHORITY/v2"
VALIDATOR_DOMAIN = b"PTCG/EXACT_GATE/VALIDATOR/v2"
DEPENDENCY_DOMAIN = b"PTCG/EXACT_GATE/DEPENDENCY_CLOSURE/v2\0"

MAX_WIRE_BYTES = 2**31 - 1
MAX_CANONICAL_JSON_BYTES = 2**31 - 1
MAX_JSON_DEPTH = 64
MAX_COLLECTION_ITEMS = 1_000_000
MAX_MANIFEST_ENTRIES = 500_000
MAX_ARTIFACT_BYTES = 2**31 - 1
MAX_PATH_BYTES = 1_024
MAX_UINT64 = 2**64 - 1

PASS_DECISION = "PASS_RESEARCH_ONLY"
FAIL_DECISION = "FAIL_CLOSED"
REJECTED_DECISION = "REJECTED_INVALID_ENVELOPE"
DEPENDENCY_FAILURE_CODE = "DEPENDENCY_FAILED"

# A code change plus a new source freeze is required to add a dispatcher.
EXACT_V2_VERIFIER_ALLOWLIST: Mapping[str, object] = MappingProxyType({})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GATE_RE = re.compile(r"^G(?:0[0-9]|1[0-5])_[A-Z0-9_]+$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_NS_RE = re.compile(r"^(?:0|[1-9][0-9]{0,20})$")
_FAILURE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_MEDIA_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")

_ED25519_P = 2**255 - 19
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_SQRT_M1 = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)
_ED25519_L = 2**252 + 27742317777372353535851937790883648493

_BYTE_FIELDS = frozenset({"base64", "decoded_length", "sha256", "media_type"})
_ENVELOPE_FIELDS = frozenset(
    {"schema_version", "signer_key_id", "payload", "signature_ed25519_base64"}
)
_FINAL_BUNDLE_FIELDS = frozenset(
    {"schema_version", "authority_envelope", "validator_envelope"}
)
_DEPENDENCY_FIELDS = frozenset(
    {"gate_id", "bundle_sha256", "authority_payload_sha256", "decision"}
)
_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "campaign_root",
        "freeze_registry_epoch",
        "freeze_registry_hash",
        "evaluation_entry_hash",
        "evaluation_id",
        "evaluation_nonce",
        "gate_id",
        "attempt",
        "frozen_spec_hash",
        "input_schema_hash",
        "output_schema_hash",
        "failure_code_registry_hash",
        "evidence_manifest_envelope_sha256",
        "evidence_manifest_root",
        "verifier_bundle_digest",
        "verifier_runtime_digest",
        "direct_dependencies",
        "dependency_closure_root",
        "input_bundle_root",
        "recomputed_outputs",
        "decision",
        "failure_codes",
        "issued_at_ns",
    }
)
_VALIDATOR_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "campaign_root",
        "validation_registry_epoch",
        "validation_registry_hash",
        "evaluation_id",
        "evaluation_nonce",
        "gate_id",
        "attempt",
        "authority_envelope_sha256",
        "authority_envelope_decoded_length",
        "authority_payload_sha256",
        "input_bundle_root",
        "verifier_bundle_digest",
        "verifier_runtime_digest",
        "validator_recomputed_outputs_sha256",
        "validator_failure_codes_sha256",
        "decision",
        "issued_at_ns",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "evaluation_entry_hash",
        "evaluation_id",
        "evaluation_nonce",
        "gate_id",
        "attempt",
        "issued_at_ns",
        "entries",
        "merkle_root",
    }
)
_MANIFEST_ENTRY_FIELDS = frozenset(
    {"artifact_id", "path", "decoded_length", "sha256", "media_type"}
)
_SUPPLIED_ARTIFACT_FIELDS = frozenset({"artifact_id", "path", "content"})
_DEPENDENCY_EDGE_FIELDS = frozenset({"gate_id", "dependency_gate_id"})


class ExactGateV2Error(ValueError):
    """A v2 wire object or closure invariant is invalid."""


class ReplayConflictError(ExactGateV2Error):
    """A different bundle reused a prospectively registered one-shot key."""


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ExactGateV2Error(f"{label} fields are not exact")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ExactGateV2Error(f"{label} must be lowercase SHA-256 hex")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise ExactGateV2Error(f"{label} is not a canonical identifier")
    return value


def _artifact_id(value: object, label: str) -> str:
    if type(value) is not str or _ARTIFACT_ID_RE.fullmatch(value) is None:
        raise ExactGateV2Error(f"{label} is not a canonical artifact identifier")
    return value


def _gate_id(value: object, label: str = "gate_id") -> str:
    if type(value) is not str or _GATE_RE.fullmatch(value) is None:
        raise ExactGateV2Error(f"{label} is not a canonical G00-G15 gate id")
    return value


def _ns(value: object, label: str) -> str:
    if (
        type(value) is not str
        or _NS_RE.fullmatch(value) is None
        or int(value) > MAX_UINT64
    ):
        raise ExactGateV2Error(f"{label} must be canonical nonnegative decimal nanoseconds")
    return value


def _path(value: object, label: str) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise ExactGateV2Error(f"{label} is not a normalized relative POSIX path")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ExactGateV2Error(f"{label} must be ASCII") from exc
    if value.startswith("/") or "\\" in value or "//" in value:
        raise ExactGateV2Error(f"{label} is not a normalized relative POSIX path")
    parts = value.split("/")
    if any(
        part in {"", ".", ".."} or _PATH_SEGMENT_RE.fullmatch(part) is None
        for part in parts
    ):
        raise ExactGateV2Error(f"{label} is not a normalized relative POSIX path")
    return value


def _uint64(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_UINT64:
        raise ExactGateV2Error(f"{label} must be an unsigned 64-bit integer")
    return value


def _reject_floats(value: object, *, path: str = "$", depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ExactGateV2Error(f"{path} exceeds the frozen JSON depth limit")
    if type(value) is float:
        raise ExactGateV2Error(f"{path} contains a forbidden JSON float")
    if type(value) is int:
        _uint64(value, path)
    if type(value) is dict:
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ExactGateV2Error(f"{path} exceeds the frozen object size limit")
        for key, child in value.items():
            if type(key) is not str:
                raise ExactGateV2Error(f"{path} has a non-string key")
            _reject_floats(child, path=f"{path}.{key}", depth=depth + 1)
    elif type(value) is list:
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ExactGateV2Error(f"{path} exceeds the frozen array size limit")
        for index, child in enumerate(value):
            _reject_floats(child, path=f"{path}[{index}]", depth=depth + 1)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExactGateV2Error("canonical JSON contains a duplicate key")
        result[key] = value
    return result


def strict_canonical_json(raw: bytes, *, label: str) -> Any:
    """Decode exact canonical JSON with no floats or duplicate keys."""

    if type(raw) is not bytes:
        raise ExactGateV2Error(f"{label} must be bytes")
    if len(raw) > MAX_CANONICAL_JSON_BYTES:
        raise ExactGateV2Error(f"{label} exceeds the frozen JSON byte limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_int=int,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ExactGateV2Error("JSON floats are forbidden")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ExactGateV2Error("nonfinite JSON numbers are forbidden")
            ),
        )
    except ExactGateV2Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ExactGateV2Error(f"{label} is not strict UTF-8 JSON") from exc
    _reject_floats(value)
    try:
        recoded = canonical_json_bytes(value)
    except CanonicalJSONError as exc:
        raise ExactGateV2Error(f"{label} is not canonical JSON") from exc
    if recoded != raw:
        raise ExactGateV2Error(f"{label} bytes are not canonical JSON")
    return value


def encode_byte_evidence(raw: bytes, *, media_type: str) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ExactGateV2Error("byte evidence must be bytes")
    if len(raw) > MAX_WIRE_BYTES:
        raise ExactGateV2Error("byte evidence exceeds the frozen byte limit")
    if type(media_type) is not str or _MEDIA_TYPE_RE.fullmatch(media_type) is None:
        raise ExactGateV2Error("media_type is not canonical")
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "decoded_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "media_type": media_type,
    }


def decode_byte_evidence(
    value: object,
    *,
    expected_media_type: str | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    record = _exact(value, _BYTE_FIELDS, "byte evidence")
    encoded = record["base64"]
    if type(encoded) is not str:
        raise ExactGateV2Error("byte evidence base64 must be a string")
    length = record["decoded_length"]
    if type(length) is not int or length < 0 or length > MAX_WIRE_BYTES:
        raise ExactGateV2Error("byte evidence decoded_length is invalid")
    if len(encoded) > ((MAX_WIRE_BYTES + 2) // 3) * 4:
        raise ExactGateV2Error("byte evidence base64 exceeds the frozen byte limit")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ExactGateV2Error("byte evidence is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise ExactGateV2Error("byte evidence is not canonical base64")
    if length != len(raw):
        raise ExactGateV2Error("byte evidence decoded_length mismatch")
    digest = _sha256(record["sha256"], "byte evidence sha256")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ExactGateV2Error("byte evidence sha256 mismatch")
    media_type = record["media_type"]
    if type(media_type) is not str or _MEDIA_TYPE_RE.fullmatch(media_type) is None:
        raise ExactGateV2Error("byte evidence media_type is invalid")
    if expected_media_type is not None and media_type != expected_media_type:
        raise ExactGateV2Error("byte evidence media_type mismatch")
    if expected_sha256 is not None and digest != _sha256(expected_sha256, "expected sha256"):
        raise ExactGateV2Error("byte evidence expected sha256 mismatch")
    return raw


def _length_delimited(raw: bytes) -> bytes:
    return len(raw).to_bytes(8, "big") + raw


def _u64be(value: int) -> bytes:
    return _uint64(value, "u64 value").to_bytes(8, "big")


def _merkle_root(records: Sequence[Mapping[str, Any]]) -> str:
    ordered = sorted(
        (dict(record) for record in records),
        key=lambda row: (row["artifact_id"].encode("utf-8"), row["path"].encode("utf-8")),
    )
    count = len(ordered)
    if count == 0:
        return hashlib.sha256(b"\x03" + _u64be(0)).hexdigest()
    leaves = []
    for index, record in enumerate(ordered):
        raw = canonical_json_bytes(record)
        leaves.append(
            hashlib.sha256(b"\x00" + _u64be(index) + _u64be(len(raw)) + raw).digest()
        )
    target = 1
    while target < len(leaves):
        target *= 2
    for index in range(len(leaves), target):
        leaves.append(hashlib.sha256(b"\x02" + _u64be(index) + _u64be(count)).digest())
    while len(leaves) > 1:
        leaves = [
            hashlib.sha256(b"\x01" + left + right).digest()
            for left, right in zip(leaves[0::2], leaves[1::2], strict=True)
        ]
    return hashlib.sha256(b"\x03" + _u64be(count) + leaves[0]).hexdigest()


def evidence_merkle_root(records: Sequence[Mapping[str, Any]]) -> str:
    """Return the domain-separated Merkle root for normalized manifest rows."""

    normalized = [dict(record) for record in records]
    _reject_floats(normalized)
    return _merkle_root(normalized)


def validate_evidence_manifest(
    manifest_wrapper: object,
    supplied_artifacts: object,
) -> dict[str, Any]:
    """Recompute one-to-one artifact closure and the frozen Merkle root."""

    raw = decode_byte_evidence(
        manifest_wrapper, expected_media_type=MANIFEST_MEDIA_TYPE
    )
    manifest = _exact(
        strict_canonical_json(raw, label="evidence manifest"),
        _MANIFEST_FIELDS,
        "evidence manifest",
    )
    if manifest["schema_version"] != EVIDENCE_MANIFEST_SCHEMA:
        raise ExactGateV2Error("evidence manifest schema mismatch")
    _sha256(manifest["evaluation_entry_hash"], "evaluation entry hash")
    _identifier(manifest["evaluation_id"], "evaluation_id")
    _sha256(manifest["evaluation_nonce"], "evaluation_nonce")
    _gate_id(manifest["gate_id"])
    if type(manifest["attempt"]) is not int or manifest["attempt"] != 0:
        raise ExactGateV2Error("exact-gate attempt must be zero")
    _ns(manifest["issued_at_ns"], "manifest issued_at_ns")

    entries = manifest["entries"]
    if (
        type(entries) is not list
        or not entries
        or len(entries) > MAX_MANIFEST_ENTRIES
    ):
        raise ExactGateV2Error("manifest entries must be a nonempty list")
    normalized_entries: list[dict[str, Any]] = []
    entry_ids: set[str] = set()
    entry_paths: set[str] = set()
    for value in entries:
        entry = _exact(value, _MANIFEST_ENTRY_FIELDS, "manifest entry")
        artifact_id = _artifact_id(entry["artifact_id"], "artifact_id")
        path = _path(entry["path"], "artifact path")
        length = entry["decoded_length"]
        if type(length) is not int or length < 0 or length > MAX_ARTIFACT_BYTES:
            raise ExactGateV2Error("artifact decoded_length is invalid")
        digest = _sha256(entry["sha256"], "artifact sha256")
        media_type = entry["media_type"]
        if type(media_type) is not str or _MEDIA_TYPE_RE.fullmatch(media_type) is None:
            raise ExactGateV2Error("artifact media_type is invalid")
        if artifact_id in entry_ids or path in entry_paths:
            raise ExactGateV2Error("manifest has duplicate artifact identifiers or paths")
        entry_ids.add(artifact_id)
        entry_paths.add(path)
        normalized_entries.append(
            {
                "artifact_id": artifact_id,
                "path": path,
                "decoded_length": length,
                "sha256": digest,
                "media_type": media_type,
            }
        )
    if normalized_entries != sorted(
        normalized_entries,
        key=lambda row: (row["artifact_id"].encode("utf-8"), row["path"].encode("utf-8")),
    ):
        raise ExactGateV2Error("manifest entries must be artifact-id/path byte sorted")

    if type(supplied_artifacts) is not list:
        raise ExactGateV2Error("supplied artifacts must be a list")
    supplied: dict[str, tuple[str, dict[str, Any]]] = {}
    supplied_paths: set[str] = set()
    for value in supplied_artifacts:
        artifact = _exact(value, _SUPPLIED_ARTIFACT_FIELDS, "supplied artifact")
        artifact_id = _artifact_id(artifact["artifact_id"], "supplied artifact_id")
        path = _path(artifact["path"], "supplied artifact path")
        if artifact_id in supplied or path in supplied_paths:
            raise ExactGateV2Error("supplied artifacts contain duplicates")
        content = _exact(artifact["content"], _BYTE_FIELDS, "supplied content")
        decode_byte_evidence(content)
        supplied[artifact_id] = (path, content)
        supplied_paths.add(path)
    if set(supplied) != entry_ids:
        raise ExactGateV2Error("manifest/artifact closure has omissions or extras")
    for entry in normalized_entries:
        path, content = supplied[entry["artifact_id"]]
        if path != entry["path"] or {
            key: content[key]
            for key in ("decoded_length", "sha256", "media_type")
        } != {
            key: entry[key]
            for key in ("decoded_length", "sha256", "media_type")
        }:
            raise ExactGateV2Error("manifest entry does not bind exact supplied bytes")
    root = _merkle_root(normalized_entries)
    if _sha256(manifest["merkle_root"], "manifest merkle_root") != root:
        raise ExactGateV2Error("manifest Merkle root mismatch")
    return {
        "manifest": manifest,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "merkle_root": root,
        "artifact_count": len(normalized_entries),
    }


def normalize_direct_dependencies(
    value: object, *, require_pass: bool = False
) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > 16:
        raise ExactGateV2Error("direct_dependencies must be a list")
    result: list[dict[str, Any]] = []
    previous = ""
    for item in value:
        row = _exact(item, _DEPENDENCY_FIELDS, "direct dependency")
        gate = _gate_id(row["gate_id"], "dependency gate_id")
        if gate <= previous:
            raise ExactGateV2Error("direct dependencies must be unique and gate-id sorted")
        previous = gate
        decision = row["decision"]
        if decision not in {PASS_DECISION, FAIL_DECISION}:
            raise ExactGateV2Error("dependency decision is invalid")
        if require_pass and decision != PASS_DECISION:
            raise ExactGateV2Error("a passing gate cannot contain a failed dependency")
        result.append(
            {
                "gate_id": gate,
                "bundle_sha256": _sha256(row["bundle_sha256"], "dependency bundle"),
                "authority_payload_sha256": _sha256(
                    row["authority_payload_sha256"], "dependency payload"
                ),
                "decision": decision,
            }
        )
    return result


def _normalize_dependency_nodes(value: object) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > 16:
        raise ExactGateV2Error("dependency nodes must be a bounded list")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        row = normalize_direct_dependencies([item])[0]
        if row["gate_id"] in seen:
            raise ExactGateV2Error("dependency graph contains a duplicate node")
        seen.add(row["gate_id"])
        result.append(row)
    return sorted(result, key=lambda row: row["gate_id"].encode("ascii"))


def _normalize_dependency_edges(value: object) -> list[dict[str, str]]:
    if type(value) is not list or len(value) > 256:
        raise ExactGateV2Error("dependency edges must be a list")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        row = _exact(item, _DEPENDENCY_EDGE_FIELDS, "dependency edge")
        edge = {
            "gate_id": _gate_id(row["gate_id"], "edge gate_id"),
            "dependency_gate_id": _gate_id(
                row["dependency_gate_id"], "edge dependency_gate_id"
            ),
        }
        key = (edge["gate_id"], edge["dependency_gate_id"])
        if key in seen:
            raise ExactGateV2Error("dependency graph contains a duplicate edge")
        if key[0] == key[1]:
            raise ExactGateV2Error("dependency graph contains a self-cycle")
        seen.add(key)
        result.append(edge)
    return sorted(
        result,
        key=lambda row: (
            row["gate_id"].encode("ascii"),
            row["dependency_gate_id"].encode("ascii"),
        ),
    )


def dependency_closure_root(
    records: object,
    edges: object,
    *,
    current_gate_id: str,
) -> str:
    """Commit the complete ancestor node set and every reachable DAG edge."""

    normalized_nodes = _normalize_dependency_nodes(records)
    normalized_edges = _normalize_dependency_edges(edges)
    body = canonical_json_bytes(
        {
            "schema_version": "ptcg.exact_gate.dependency-closure/v2",
            "current_gate_id": _gate_id(current_gate_id, "current gate_id"),
            "nodes": normalized_nodes,
            "edges": normalized_edges,
        }
    )
    return hashlib.sha256(DEPENDENCY_DOMAIN + _length_delimited(body)).hexdigest()


def validate_registered_dependency_closure(
    *,
    current_gate_id: str,
    current_decision: str,
    direct_dependencies: object,
    registered_direct_gate_ids: Sequence[str],
    transitive_dependencies: object,
    transitive_edges: object,
    registered_transitive_edges: object,
    expected_closure_root: str,
) -> dict[str, Any]:
    """Check registered direct edges and a recomputed transitive closure."""

    current_gate = _gate_id(current_gate_id, "current gate_id")
    direct = normalize_direct_dependencies(direct_dependencies)
    expected_ids = [_gate_id(item, "registered dependency gate_id") for item in registered_direct_gate_ids]
    if expected_ids != sorted(set(expected_ids)):
        raise ExactGateV2Error("registered direct dependencies are not canonical")
    if [item["gate_id"] for item in direct] != expected_ids:
        raise ExactGateV2Error("direct dependency set differs from registered DAG")
    closure = _normalize_dependency_nodes(transitive_dependencies)
    edges = _normalize_dependency_edges(transitive_edges)
    registered_edges = _normalize_dependency_edges(registered_transitive_edges)
    if edges != registered_edges:
        raise ExactGateV2Error("dependency edges differ from the registered full DAG")
    closure_ids = {item["gate_id"] for item in closure}
    closure_by_gate = {item["gate_id"]: item for item in closure}
    if current_gate in closure_ids:
        raise ExactGateV2Error("dependency closure contains a cycle")
    if not set(expected_ids).issubset(closure_ids):
        raise ExactGateV2Error("dependency closure omits a direct dependency")
    if any(closure_by_gate[item["gate_id"]] != item for item in direct):
        raise ExactGateV2Error(
            "direct dependency record conflicts with its closure node"
        )
    if current_gate != "G00_TRUST_ROOTS" and "G00_TRUST_ROOTS" not in closure_ids:
        raise ExactGateV2Error("downstream dependency closure omits G00")
    if current_decision not in {PASS_DECISION, FAIL_DECISION}:
        raise ExactGateV2Error("current decision is invalid")
    permitted_sources = closure_ids | {current_gate}
    for edge in edges:
        if (
            edge["gate_id"] not in permitted_sources
            or edge["dependency_gate_id"] not in closure_ids
        ):
            raise ExactGateV2Error("dependency edge references an unknown closure node")
    current_edges = [
        edge["dependency_gate_id"] for edge in edges if edge["gate_id"] == current_gate
    ]
    if current_edges != expected_ids:
        raise ExactGateV2Error("dependency graph current edges differ from registered DAG")

    adjacency: dict[str, list[str]] = {gate: [] for gate in permitted_sources}
    for edge in edges:
        adjacency[edge["gate_id"]].append(edge["dependency_gate_id"])
    state: dict[str, int] = {}

    def visit(gate: str) -> None:
        marker = state.get(gate, 0)
        if marker == 1:
            raise ExactGateV2Error("dependency graph contains a reachable cycle")
        if marker == 2:
            return
        state[gate] = 1
        for dependency in adjacency.get(gate, []):
            visit(dependency)
        state[gate] = 2

    visit(current_gate)
    reachable = {gate for gate, marker in state.items() if marker == 2}
    if reachable != permitted_sources:
        raise ExactGateV2Error("dependency graph contains missing or unreachable nodes")
    if dependency_closure_root(
        closure, edges, current_gate_id=current_gate
    ) != _sha256(
        expected_closure_root, "expected dependency closure root"
    ):
        raise ExactGateV2Error("dependency closure root mismatch")
    failed = sorted(
        item["gate_id"] for item in closure if item["decision"] == FAIL_DECISION
    )
    return {
        "nodes": closure,
        "edges": edges,
        "recomputed_outputs": {"failed_dependency_gate_ids": failed},
        "forced_failure_codes": [DEPENDENCY_FAILURE_CODE] if failed else [],
        "forced_decision": FAIL_DECISION if failed else current_decision,
    }


def enforce_dependency_effect(
    *,
    module_recomputed_outputs: object,
    module_failure_codes: object,
    dependency_result: Mapping[str, Any],
    frozen_failure_codes: frozenset[str],
) -> dict[str, Any]:
    """Apply dependency failure in the shared verifier, never in gate code."""

    if type(module_recomputed_outputs) is not dict:
        raise ExactGateV2Error("module recomputed outputs must be an exact object")
    _reject_floats(module_recomputed_outputs, path="$.module_recomputed_outputs")
    if type(module_failure_codes) is not list or module_failure_codes != sorted(
        set(module_failure_codes)
    ):
        raise ExactGateV2Error("module failure codes are not unique and sorted")
    if any(
        type(code) is not str
        or _FAILURE_RE.fullmatch(code) is None
        or code not in frozen_failure_codes
        for code in module_failure_codes
    ):
        raise ExactGateV2Error("module failure codes are not in the frozen registry")
    effect = _exact(
        dict(dependency_result),
        frozenset(
            {
                "nodes",
                "edges",
                "recomputed_outputs",
                "forced_failure_codes",
                "forced_decision",
            }
        ),
        "dependency effect",
    )
    failed_output = _exact(
        effect["recomputed_outputs"],
        frozenset({"failed_dependency_gate_ids"}),
        "dependency recomputed outputs",
    )
    failed_ids = failed_output["failed_dependency_gate_ids"]
    if type(failed_ids) is not list or failed_ids != sorted(set(failed_ids)):
        raise ExactGateV2Error("failed dependency IDs are not unique and sorted")
    for gate in failed_ids:
        _gate_id(gate, "failed dependency gate_id")
    expected_forced_codes = [DEPENDENCY_FAILURE_CODE] if failed_ids else []
    if effect["forced_failure_codes"] != expected_forced_codes:
        raise ExactGateV2Error("dependency failure-code effect is inconsistent")
    if DEPENDENCY_FAILURE_CODE not in frozen_failure_codes and failed_ids:
        raise ExactGateV2Error("dependency failure code is absent from frozen registry")

    outputs = dict(module_recomputed_outputs)
    outputs["failed_dependency_gate_ids"] = failed_ids
    codes = sorted(set(module_failure_codes) | set(expected_forced_codes))
    decision = FAIL_DECISION if codes else PASS_DECISION
    return {
        "recomputed_outputs": outputs,
        "failure_codes": codes,
        "decision": decision,
    }


def _failure_codes(
    value: object,
    *,
    decision: str,
    frozen_registry: frozenset[str],
) -> list[str]:
    if type(value) is not list or any(
        type(item) is not str or _FAILURE_RE.fullmatch(item) is None for item in value
    ):
        raise ExactGateV2Error("failure codes are not canonical")
    if len(value) > 256:
        raise ExactGateV2Error("failure-code list exceeds the frozen size limit")
    if value != sorted(set(value)) or any(item not in frozen_registry for item in value):
        raise ExactGateV2Error("failure codes are not in the frozen registry")
    if decision == PASS_DECISION and value:
        raise ExactGateV2Error("passing result contains failure codes")
    if decision == FAIL_DECISION and not value:
        raise ExactGateV2Error("failed result has no failure codes")
    return list(value)


def parse_authority_payload(
    raw: bytes,
    *,
    frozen_failure_codes: frozenset[str],
) -> dict[str, Any]:
    value = _exact(
        strict_canonical_json(raw, label="authority payload"),
        _AUTHORITY_FIELDS,
        "authority payload",
    )
    if value["schema_version"] != AUTHORITY_PAYLOAD_SCHEMA or value["protocol_id"] != PROTOCOL_ID:
        raise ExactGateV2Error("authority payload schema or protocol mismatch")
    for field in (
        "campaign_root",
        "freeze_registry_hash",
        "evaluation_entry_hash",
        "evaluation_nonce",
        "frozen_spec_hash",
        "input_schema_hash",
        "output_schema_hash",
        "failure_code_registry_hash",
        "evidence_manifest_envelope_sha256",
        "evidence_manifest_root",
        "verifier_bundle_digest",
        "verifier_runtime_digest",
        "dependency_closure_root",
        "input_bundle_root",
    ):
        _sha256(value[field], field)
    _identifier(value["evaluation_id"], "evaluation_id")
    _gate_id(value["gate_id"])
    _uint64(value["freeze_registry_epoch"], "freeze registry epoch")
    if type(value["attempt"]) is not int or value["attempt"] != 0:
        raise ExactGateV2Error("exact-gate attempt must be zero")
    _ns(value["issued_at_ns"], "authority issued_at_ns")
    normalize_direct_dependencies(value["direct_dependencies"])
    if type(value["recomputed_outputs"]) is not dict:
        raise ExactGateV2Error("recomputed outputs must be an exact gate object")
    _reject_floats(value["recomputed_outputs"], path="$.recomputed_outputs")
    decision = value["decision"]
    if decision not in {PASS_DECISION, FAIL_DECISION}:
        raise ExactGateV2Error("authority decision is invalid")
    _failure_codes(
        value["failure_codes"],
        decision=decision,
        frozen_registry=frozen_failure_codes,
    )
    return value


def parse_validator_payload(raw: bytes) -> dict[str, Any]:
    value = _exact(
        strict_canonical_json(raw, label="validator payload"),
        _VALIDATOR_FIELDS,
        "validator payload",
    )
    if value["schema_version"] != VALIDATOR_PAYLOAD_SCHEMA or value["protocol_id"] != PROTOCOL_ID:
        raise ExactGateV2Error("validator payload schema or protocol mismatch")
    for field in (
        "campaign_root",
        "validation_registry_hash",
        "evaluation_nonce",
        "authority_envelope_sha256",
        "authority_payload_sha256",
        "input_bundle_root",
        "verifier_bundle_digest",
        "verifier_runtime_digest",
        "validator_recomputed_outputs_sha256",
        "validator_failure_codes_sha256",
    ):
        _sha256(value[field], field)
    _identifier(value["evaluation_id"], "evaluation_id")
    _gate_id(value["gate_id"])
    _uint64(value["validation_registry_epoch"], "validation registry epoch")
    if type(value["attempt"]) is not int or value["attempt"] != 0:
        raise ExactGateV2Error("exact-gate attempt must be zero")
    length = value["authority_envelope_decoded_length"]
    if type(length) is not int or length < 0 or length > MAX_WIRE_BYTES:
        raise ExactGateV2Error("authority envelope decoded length is invalid")
    if value["decision"] not in {PASS_DECISION, FAIL_DECISION}:
        raise ExactGateV2Error("validator decision is invalid")
    _ns(value["issued_at_ns"], "validator issued_at_ns")
    return value


def cross_check_validator_payload(
    *,
    authority_envelope_raw: bytes,
    authority_payload_raw: bytes,
    authority_payload: Mapping[str, Any],
    validator_payload: Mapping[str, Any],
) -> None:
    """Check exact authority/validator agreement without granting key trust."""

    authority = dict(authority_payload)
    validator = dict(validator_payload)
    checks = {
        "campaign_root": authority["campaign_root"],
        "evaluation_id": authority["evaluation_id"],
        "evaluation_nonce": authority["evaluation_nonce"],
        "gate_id": authority["gate_id"],
        "attempt": authority["attempt"],
        "input_bundle_root": authority["input_bundle_root"],
        "verifier_bundle_digest": authority["verifier_bundle_digest"],
        "verifier_runtime_digest": authority["verifier_runtime_digest"],
        "decision": authority["decision"],
    }
    for field, expected in checks.items():
        if validator[field] != expected:
            raise ExactGateV2Error(f"validator {field} does not match authority")
    if validator["authority_envelope_sha256"] != hashlib.sha256(authority_envelope_raw).hexdigest():
        raise ExactGateV2Error("validator does not bind exact authority envelope bytes")
    if validator["authority_envelope_decoded_length"] != len(authority_envelope_raw):
        raise ExactGateV2Error("validator authority envelope length mismatch")
    if validator["authority_payload_sha256"] != hashlib.sha256(authority_payload_raw).hexdigest():
        raise ExactGateV2Error("validator does not bind exact authority payload bytes")
    if validator["validator_recomputed_outputs_sha256"] != canonical_sha256(
        authority["recomputed_outputs"]
    ):
        raise ExactGateV2Error("validator recomputed output hash differs from authority")
    if validator["validator_failure_codes_sha256"] != canonical_sha256(
        authority["failure_codes"]
    ):
        raise ExactGateV2Error("validator failure-code hash differs from authority")
    if validator["validation_registry_epoch"] < authority["freeze_registry_epoch"]:
        raise ExactGateV2Error("validator selected a stale registry epoch")
    # Signer-supplied timestamps are key-validity inputs only. Causal succession
    # comes from the validator binding the exact authority envelope bytes.
    if int(validator["issued_at_ns"]) < int(authority["issued_at_ns"]):
        raise ExactGateV2Error("validator timestamp is chronologically inconsistent")


def _key_id(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ExactGateV2Error("Ed25519 public key is invalid")
    _decode_ed25519_point(public_key, label="Ed25519 public key", reject_small_order=True)
    return f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"


def _decode_ed25519_point(
    encoded: bytes,
    *,
    label: str,
    reject_small_order: bool,
) -> tuple[int, int]:
    if type(encoded) is not bytes or len(encoded) != 32:
        raise ExactGateV2Error(f"{label} must encode exactly 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _ED25519_P:
        raise ExactGateV2Error(f"{label} has a noncanonical field encoding")
    y2 = y * y % _ED25519_P
    denominator = (_ED25519_D * y2 + 1) % _ED25519_P
    if denominator == 0:
        raise ExactGateV2Error(f"{label} is not an Edwards25519 point")
    x2 = (y2 - 1) * pow(denominator, _ED25519_P - 2, _ED25519_P) % _ED25519_P
    x = pow(x2, (_ED25519_P + 3) // 8, _ED25519_P)
    if x * x % _ED25519_P != x2:
        x = x * _ED25519_SQRT_M1 % _ED25519_P
    if x * x % _ED25519_P != x2:
        raise ExactGateV2Error(f"{label} is not an Edwards25519 point")
    if (x & 1) != sign:
        x = (-x) % _ED25519_P
    if x == 0 and sign:
        raise ExactGateV2Error(f"{label} has a noncanonical sign bit")
    point = (x, y)
    if reject_small_order:
        extended = _ed25519_extended(point)
        cofactored = extended
        for _ in range(3):
            cofactored = _ed25519_extended_double(cofactored)
        if _ed25519_extended_is_identity(cofactored):
            raise ExactGateV2Error(f"{label} has small order")
        if not _ed25519_extended_is_identity(
            _ed25519_extended_scalar_multiply(extended, _ED25519_L)
        ):
            raise ExactGateV2Error(f"{label} is not in the prime-order subgroup")
    return point


def _ed25519_add(
    left: tuple[int, int], right: tuple[int, int]
) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = _ED25519_D * x1 * x2 * y1 * y2 % _ED25519_P
    denominator_x = (1 + product) % _ED25519_P
    denominator_y = (1 - product) % _ED25519_P
    if denominator_x == 0 or denominator_y == 0:
        raise ExactGateV2Error("Edwards25519 addition denominator is zero")
    x3 = (x1 * y2 + y1 * x2) * pow(
        denominator_x, _ED25519_P - 2, _ED25519_P
    ) % _ED25519_P
    y3 = (y1 * y2 + x1 * x2) * pow(
        denominator_y, _ED25519_P - 2, _ED25519_P
    ) % _ED25519_P
    return x3, y3


def _ed25519_extended(point: tuple[int, int]) -> tuple[int, int, int, int]:
    x, y = point
    return x, y, 1, x * y % _ED25519_P


def _ed25519_extended_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED25519_P
    b = (y1 + x1) * (y2 + x2) % _ED25519_P
    c = 2 * _ED25519_D * t1 * t2 % _ED25519_P
    d = 2 * z1 * z2 % _ED25519_P
    e = (b - a) % _ED25519_P
    f = (d - c) % _ED25519_P
    g = (d + c) % _ED25519_P
    h = (b + a) % _ED25519_P
    return e * f % _ED25519_P, g * h % _ED25519_P, f * g % _ED25519_P, e * h % _ED25519_P


def _ed25519_extended_double(
    point: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    a = x * x % _ED25519_P
    b = y * y % _ED25519_P
    c = 2 * z * z % _ED25519_P
    d = (-a) % _ED25519_P
    e = ((x + y) * (x + y) - a - b) % _ED25519_P
    g = (d + b) % _ED25519_P
    f = (g - c) % _ED25519_P
    h = (d - b) % _ED25519_P
    return e * f % _ED25519_P, g * h % _ED25519_P, f * g % _ED25519_P, e * h % _ED25519_P


def _ed25519_extended_scalar_multiply(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    addend = point
    remaining = scalar
    while remaining:
        if remaining & 1:
            result = _ed25519_extended_add(result, addend)
        addend = _ed25519_extended_double(addend)
        remaining >>= 1
    return result


def _ed25519_extended_is_identity(
    point: tuple[int, int, int, int]
) -> bool:
    x, y, z, _ = point
    return x % _ED25519_P == 0 and (y - z) % _ED25519_P == 0


def _validate_ed25519_signature_encoding(signature: bytes) -> None:
    if type(signature) is not bytes or len(signature) != 64:
        raise ExactGateV2Error("Ed25519 signature must encode exactly 64 bytes")
    _decode_ed25519_point(
        signature[:32], label="Ed25519 signature R", reject_small_order=True
    )
    if int.from_bytes(signature[32:], "little") >= _ED25519_L:
        raise ExactGateV2Error("Ed25519 signature scalar is noncanonical")


def validate_ed25519_public_key(public_key: bytes) -> str:
    """Validate strict prime-subgroup encoding and return its fixed key ID."""

    return _key_id(public_key)


def validate_ed25519_signature_encoding(signature: bytes) -> None:
    """Reject noncanonical, torsion, mixed-order, or out-of-range signatures."""

    _validate_ed25519_signature_encoding(signature)


def signature_message(*, domain: bytes, payload_wrapper: object) -> bytes:
    payload = _exact(payload_wrapper, _BYTE_FIELDS, "signed payload wrapper")
    raw = decode_byte_evidence(payload)
    if domain not in {AUTHORITY_DOMAIN, VALIDATOR_DOMAIN}:
        raise ExactGateV2Error("signature domain is not frozen")
    strict_canonical_json(raw, label="signed payload")
    return domain + b"\x00" + _u64be(len(raw)) + raw


def verify_signed_payload_envelope(
    raw_envelope: bytes,
    *,
    expected_schema: str,
    expected_payload_media_type: str,
    public_key: bytes,
    domain: bytes,
) -> bytes:
    envelope = _exact(
        strict_canonical_json(raw_envelope, label="signed envelope"),
        _ENVELOPE_FIELDS,
        "signed envelope",
    )
    if envelope["schema_version"] != expected_schema:
        raise ExactGateV2Error("signed envelope schema mismatch")
    if envelope["signer_key_id"] != _key_id(public_key):
        raise ExactGateV2Error("signed envelope key id mismatch")
    payload = decode_byte_evidence(
        envelope["payload"], expected_media_type=expected_payload_media_type
    )
    # Verify the exact canonical payload bytes carried by the envelope. Callers
    # then parse the typed schema and require equality to their reconstruction.
    strict_canonical_json(payload, label="signed payload")
    signature_value = envelope["signature_ed25519_base64"]
    if type(signature_value) is not str:
        raise ExactGateV2Error("signature must be canonical base64")
    try:
        signature = base64.b64decode(signature_value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ExactGateV2Error("signature must be canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_value:
        raise ExactGateV2Error("signature must encode exactly 64 bytes")
    _validate_ed25519_signature_encoding(signature)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            signature_message(domain=domain, payload_wrapper=envelope["payload"]),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ExactGateV2Error("Ed25519 signature verification failed") from exc
    return payload


def _validate_envelope_structure(
    raw: bytes,
    *,
    expected_schema: str,
    expected_payload_media_type: str,
) -> None:
    envelope = _exact(
        strict_canonical_json(raw, label="signed envelope"),
        _ENVELOPE_FIELDS,
        "signed envelope",
    )
    if envelope["schema_version"] != expected_schema:
        raise ExactGateV2Error("signed envelope schema mismatch")
    key_id = envelope["signer_key_id"]
    if type(key_id) is not str or not key_id.startswith("ed25519-sha256:") or _SHA256_RE.fullmatch(key_id[15:]) is None:
        raise ExactGateV2Error("signed envelope key id is invalid")
    decode_byte_evidence(
        envelope["payload"], expected_media_type=expected_payload_media_type
    )
    signature = envelope["signature_ed25519_base64"]
    if type(signature) is not str:
        raise ExactGateV2Error("signature must be canonical base64")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ExactGateV2Error("signature must be canonical base64") from exc
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != signature:
        raise ExactGateV2Error("signature must encode exactly 64 bytes")


def parse_final_bundle(value: object) -> tuple[bytes, bytes, str]:
    if type(value) is bytes:
        raw_bundle = value
        parsed = strict_canonical_json(value, label="exact-gate final bundle")
    else:
        _reject_floats(value)
        raw_bundle = canonical_json_bytes(value)
        parsed = value
    bundle = _exact(parsed, _FINAL_BUNDLE_FIELDS, "exact-gate final bundle")
    if bundle["schema_version"] != FINAL_BUNDLE_SCHEMA:
        raise ExactGateV2Error("final bundle schema mismatch")
    authority = decode_byte_evidence(
        bundle["authority_envelope"], expected_media_type=AUTHORITY_MEDIA_TYPE
    )
    validator = decode_byte_evidence(
        bundle["validator_envelope"], expected_media_type=VALIDATOR_MEDIA_TYPE
    )
    _validate_envelope_structure(
        authority,
        expected_schema=AUTHORITY_ENVELOPE_SCHEMA,
        expected_payload_media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
    )
    _validate_envelope_structure(
        validator,
        expected_schema=VALIDATOR_ENVELOPE_SCHEMA,
        expected_payload_media_type=VALIDATOR_PAYLOAD_MEDIA_TYPE,
    )
    return authority, validator, hashlib.sha256(raw_bundle).hexdigest()


class DurableReplayIndex:
    """Quarantined local replay primitive; never authoritative by itself."""

    def __init__(self, path: str):
        self._connection = sqlite3.connect(path, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS exact_gate_attempts (
                campaign_root TEXT NOT NULL,
                evaluation_id TEXT NOT NULL,
                evaluation_nonce TEXT NOT NULL,
                gate_id TEXT NOT NULL,
                attempt INTEGER NOT NULL CHECK (attempt = 0),
                bundle_sha256 TEXT NOT NULL,
                conflicted INTEGER NOT NULL DEFAULT 0 CHECK (conflicted IN (0, 1)),
                PRIMARY KEY (campaign_root, evaluation_id, evaluation_nonce, gate_id, attempt)
            )
            """
        )

    def close(self) -> None:
        self._connection.close()

    def record(
        self,
        *,
        campaign_root: str,
        evaluation_id: str,
        evaluation_nonce: str,
        gate_id: str,
        attempt: int,
        bundle_sha256: str,
    ) -> str:
        del (
            campaign_root,
            evaluation_id,
            evaluation_nonce,
            gate_id,
            attempt,
            bundle_sha256,
        )
        raise ExactGateV2Error(
            "local SQLite cannot occupy the authoritative replay slot; "
            "trusted valid-only replay service integration is not implemented"
        )


def verify_exact_gate_v2(*, gate_id: str, final_bundle: object) -> dict[str, Any]:
    """Fail closed until the registered hermetic dispatcher is implemented."""

    gate = _gate_id(gate_id)
    try:
        _, _, bundle_sha256 = parse_final_bundle(final_bundle)
    except ExactGateV2Error as exc:
        return {
            "decision": REJECTED_DECISION,
            "gate_id": gate,
            "bundle_sha256": None,
            "failure_codes": ["INVALID_V2_BUNDLE"],
            "detail": str(exc),
        }
    if gate not in EXACT_V2_VERIFIER_ALLOWLIST:
        return {
            "decision": REJECTED_DECISION,
            "gate_id": gate,
            "bundle_sha256": bundle_sha256,
            "failure_codes": ["VERIFIER_NOT_ALLOWLISTED"],
            "detail": "no content-addressed hermetic v2 verifier is registered",
        }
    raise ExactGateV2Error("unreachable: v2 dispatcher registration is not implemented")


__all__ = [
    "AUTHORITY_DOMAIN",
    "AUTHORITY_ENVELOPE_SCHEMA",
    "AUTHORITY_MEDIA_TYPE",
    "AUTHORITY_PAYLOAD_SCHEMA",
    "AUTHORITY_PAYLOAD_MEDIA_TYPE",
    "DEPENDENCY_DOMAIN",
    "DEPENDENCY_FAILURE_CODE",
    "DurableReplayIndex",
    "EVIDENCE_MANIFEST_SCHEMA",
    "EXACT_V2_VERIFIER_ALLOWLIST",
    "ExactGateV2Error",
    "FAIL_DECISION",
    "FINAL_BUNDLE_SCHEMA",
    "MANIFEST_MEDIA_TYPE",
    "PASS_DECISION",
    "PROTOCOL_ID",
    "REJECTED_DECISION",
    "ReplayConflictError",
    "VALIDATOR_DOMAIN",
    "VALIDATOR_ENVELOPE_SCHEMA",
    "VALIDATOR_MEDIA_TYPE",
    "VALIDATOR_PAYLOAD_SCHEMA",
    "VALIDATOR_PAYLOAD_MEDIA_TYPE",
    "decode_byte_evidence",
    "enforce_dependency_effect",
    "cross_check_validator_payload",
    "dependency_closure_root",
    "encode_byte_evidence",
    "evidence_merkle_root",
    "normalize_direct_dependencies",
    "parse_authority_payload",
    "parse_final_bundle",
    "parse_validator_payload",
    "signature_message",
    "strict_canonical_json",
    "validate_evidence_manifest",
    "validate_ed25519_public_key",
    "validate_ed25519_signature_encoding",
    "validate_registered_dependency_closure",
    "verify_exact_gate_v2",
    "verify_signed_payload_envelope",
]
