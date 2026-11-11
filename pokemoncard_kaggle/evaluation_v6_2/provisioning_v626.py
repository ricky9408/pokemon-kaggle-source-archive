"""Negative-authority external-service provisioning readiness for v6.2.6.

This module can establish that a candidate custody package is structurally and
cryptographically complete enough for a separate policy-pinning review. It can
never pin the policy, open recruitment, issue a permit, or authorize an upload.
"""

from __future__ import annotations

import base64
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import posixpath
import re
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .evidence_v626 import EvidenceGraph, require_root, validate_evidence_graph
from .integration_v622 import canonical_json_bytes, canonical_json_loads, canonical_sha256
from .trust_v626 import (
    AUTHORITY_SCHEMA,
    ROLE_EXTERNAL_VERIFIER,
    ROLE_IDENTITY_ISSUER,
    ROLE_LOG_AUTHORITY,
    ROLE_TIME_AUTHORITY,
    ROLE_WITNESS_COSIGNER,
    validate_trust_policy,
)


PROVISIONING_PACKET_SCHEMA = "eval.v6.2.6.external-provisioning-packet"
SERVICE_RECORD_SCHEMA = "eval.v6.2.6.external-service-record"
CUSTODY_REVIEW_SCHEMA = "eval.v6.2.6.custody-review"
CUSTODY_REVIEW_ENVELOPE_SCHEMA = "eval.v6.2.6.custody-review-envelope"
ENDPOINT_PIN_EVIDENCE_SCHEMA = "eval.v6.2.6.endpoint-pin-evidence"
SERVICE_CUSTODY_EVIDENCE_SCHEMA = "eval.v6.2.6.service-custody-evidence"
SERVICE_RUNTIME_MANIFEST_SCHEMA = "eval.v6.2.6.service-runtime-manifest"
CUSTODY_REVIEW_FINDINGS_SCHEMA = "eval.v6.2.6.custody-review-findings"
CUSTODY_SOURCE_ARTIFACT_SCHEMA = "eval.v6.2.6.custody-source-artifact"
CUSTODY_REVIEWER_IDENTITY_SCHEMA = "eval.v6.2.6.custody-reviewer-identity"
CUSTODY_REVIEWER_IDENTITY_ENVELOPE_SCHEMA = (
    "eval.v6.2.6.custody-reviewer-identity-envelope"
)
PROVISIONING_VERDICT_SCHEMA = "eval.v6.2.6.external-provisioning-verdict"

ROLE_CUSTODY_REVIEWER = "CUSTODY_REVIEWER"
ROLE_RUNTIME_CUSTODIAN = "RUNTIME_CUSTODIAN"
DOMAIN_CUSTODY_REVIEW = b"EVAL-V626/CUSTODY-REVIEW\0"
DOMAIN_CUSTODY_REVIEWER_IDENTITY = b"EVAL-V626/CUSTODY-REVIEWER-IDENTITY\0"

PROVISIONING_FAILURE_STATES = frozenset(
    {
        "EXTERNAL_PROVISIONING_EVIDENCE_ABSENT",
        "PROVISIONING_PACKET_INVALID",
        "SERVICE_ROSTER_INCOMPLETE",
        "SERVICE_POLICY_MISMATCH",
        "SERVICE_CUSTODY_EVIDENCE_INCOMPLETE",
        "CUSTODY_REVIEW_QUORUM_INVALID",
        "CUSTODY_SEPARATION_INVALID",
        "EVIDENCE_GRAPH_DANGLING",
        "EVIDENCE_GRAPH_HASH_MISMATCH",
        "EVIDENCE_GRAPH_TYPE_INVALID",
        "EVIDENCE_GRAPH_PROHIBITED_CYCLE",
    }
)

_EXPECTED_ROLE_COUNTS = {
    ROLE_LOG_AUTHORITY: 1,
    ROLE_WITNESS_COSIGNER: 3,
    ROLE_TIME_AUTHORITY: 3,
    ROLE_EXTERNAL_VERIFIER: 3,
    ROLE_IDENTITY_ISSUER: 2,
    ROLE_RUNTIME_CUSTODIAN: 2,
}
_CUSTODY_CHILD_TYPES = frozenset(
    {
        "ADMIN_CONTROL_EVIDENCE",
        "STORAGE_CONTROL_EVIDENCE",
        "SERVICE_OPERATION_EVIDENCE",
        "DISASTER_RECOVERY_EVIDENCE",
        "ROLLBACK_DRILL_EVIDENCE",
        "ROTATION_PROCEDURE_EVIDENCE",
        "COMPROMISE_PROCEDURE_EVIDENCE",
        "ORGANIZATION_AUTHORITY_IDENTITY_EVIDENCE",
        "AUDIT_LOG_RETENTION_EVIDENCE",
        "EVIDENCE_EXPORT_PROCEDURE",
        "ENDPOINT_PIN_EVIDENCE",
    }
)
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ProvisioningV626Error(ValueError):
    """A candidate provisioning package failed closed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in PROVISIONING_FAILURE_STATES:
            raise ValueError(f"unknown v6.2.6 provisioning failure state: {code}")
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> ProvisioningV626Error:
    return ProvisioningV626Error(code, message)


def _exact(value: Any, fields: frozenset[str], label: str, *, code: str) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise _fail(code, f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or not value or value.strip() != value or "\0" in value:
        raise _fail(code, f"{label} must be a nonempty trimmed string without NUL")
    return value


def _sha(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or _SHA_RE.fullmatch(value) is None:
        raise _fail(code, f"{label} must be lowercase SHA-256 hex")
    return value


def _utc(value: Any, label: str, *, code: str) -> datetime:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise _fail(code, f"{label} must be canonical second-resolution UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise _fail(code, f"{label} is not a valid UTC timestamp") from exc


def _reviewer(value: Any, index: int) -> dict[str, Any]:
    code = "PROVISIONING_PACKET_INVALID"
    item = _exact(
        value,
        frozenset(
            {
                "schema",
                "key_id",
                "public_key_base64",
                "subject_id",
                "role",
                "control_group_id",
                "organization_id",
            }
        ),
        f"custody reviewer[{index}]",
        code=code,
    )
    if item["schema"] != AUTHORITY_SCHEMA or item["role"] != ROLE_CUSTODY_REVIEWER:
        raise _fail(code, "custody reviewer schema or role mismatch")
    try:
        public_key = base64.b64decode(item["public_key_base64"], validate=True)
    except Exception as exc:
        raise _fail(code, "custody reviewer public key is not canonical base64") from exc
    if len(public_key) != 32 or base64.b64encode(public_key).decode("ascii") != item["public_key_base64"]:
        raise _fail(code, "custody reviewer public key encoding is invalid")
    key_id = _identifier(item["key_id"], "custody reviewer key id", code=code)
    derived = "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()
    if _KEY_ID_RE.fullmatch(key_id) is None or key_id != derived:
        raise _fail(code, "custody reviewer key id does not match its public key")
    return {
        "key_id": key_id,
        "public_key": public_key,
        "subject_id": _identifier(item["subject_id"], "custody reviewer subject", code=code),
        "control_group_id": _identifier(item["control_group_id"], "custody reviewer control group", code=code),
        "organization_id": _identifier(item["organization_id"], "custody reviewer organization", code=code),
    }


def _reviewers(values: Any) -> dict[str, dict[str, Any]]:
    code = "PROVISIONING_PACKET_INVALID"
    if type(values) is not list or len(values) != 3:
        raise _fail(code, "exactly three custody reviewers are required")
    parsed = [_reviewer(value, index) for index, value in enumerate(values)]
    if [item["key_id"] for item in parsed] != sorted(item["key_id"] for item in parsed):
        raise _fail(code, "custody reviewers must be canonically sorted by key_id")
    for field in ("key_id", "subject_id", "control_group_id", "organization_id"):
        if len({item[field] for item in parsed}) != 3:
            raise _fail("CUSTODY_SEPARATION_INVALID", f"custody reviewers must have distinct {field} values")
    return {item["key_id"]: item for item in parsed}


def _policy_authorities(policy: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    values = [
        policy["log_authority"],
        *policy["witness_cosigners"].values(),
        *policy["time_authorities"].values(),
        *policy["verifier_authorities"].values(),
        *policy["identity_issuers"].values(),
    ]
    return {value["key_id"]: value for value in values}


_SERVICE_FIELDS = frozenset(
    {
        "schema",
        "service_id",
        "role",
        "authority_key_id",
        "subject_id",
        "control_group_id",
        "organization_id",
        "endpoint_uri",
        "endpoint_pin_sha256",
        "custody_evidence_root_sha256",
        "service_runtime_manifest_root_sha256",
    }
)


def _service_record(value: Any, index: int) -> dict[str, Any]:
    code = "PROVISIONING_PACKET_INVALID"
    item = _exact(value, _SERVICE_FIELDS, f"service record[{index}]", code=code)
    role = _identifier(item["role"], "service role", code=code)
    if item["schema"] != SERVICE_RECORD_SCHEMA or role not in _EXPECTED_ROLE_COUNTS:
        raise _fail(code, "service record schema or role mismatch")
    endpoint = _identifier(item["endpoint_uri"], "service endpoint", code=code)
    parsed_endpoint = urlparse(endpoint)
    if role == ROLE_RUNTIME_CUSTODIAN:
        if parsed_endpoint.scheme == "urn":
            if (
                endpoint != f"urn:{parsed_endpoint.path}"
                or not parsed_endpoint.path
                or parsed_endpoint.query
                or parsed_endpoint.fragment
            ):
                raise _fail(code, "runtime custodian URN endpoint is not canonical")
        elif parsed_endpoint.scheme == "https":
            _validate_https_endpoint(endpoint, parsed_endpoint, code=code)
        else:
            raise _fail(code, "runtime custodian endpoint must use https or urn")
    else:
        _validate_https_endpoint(endpoint, parsed_endpoint, code=code)
    authority_key_id = item["authority_key_id"]
    if role == ROLE_RUNTIME_CUSTODIAN:
        if authority_key_id is not None:
            raise _fail(code, "runtime custodian record must not claim an authority key")
    else:
        authority_key_id = _identifier(authority_key_id, "service authority key id", code=code)
    return {
        "raw": item,
        "sha256": canonical_sha256(item),
        "service_id": _identifier(item["service_id"], "service id", code=code),
        "role": role,
        "authority_key_id": authority_key_id,
        "subject_id": _identifier(item["subject_id"], "service subject", code=code),
        "control_group_id": _identifier(item["control_group_id"], "service control group", code=code),
        "organization_id": _identifier(item["organization_id"], "service organization", code=code),
        "endpoint_uri": endpoint,
        "endpoint_pin_sha256": _sha(item["endpoint_pin_sha256"], "endpoint pin", code=code),
        "custody_evidence_root_sha256": _sha(item["custody_evidence_root_sha256"], "custody evidence root", code=code),
        "service_runtime_manifest_root_sha256": _sha(item["service_runtime_manifest_root_sha256"], "service runtime manifest root", code=code),
    }


def _validate_https_endpoint(endpoint: str, parsed: Any, *, code: str) -> None:
    try:
        port = parsed.port
    except ValueError as exc:
        raise _fail(code, "service endpoint port is invalid") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not hostname
        or hostname != hostname.lower()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "%" in endpoint
    ):
        raise _fail(code, "external authority endpoint must use canonical absolute https")
    canonical_netloc = hostname if port in {None, 443} else f"{hostname}:{port}"
    if parsed.netloc != canonical_netloc or port == 443:
        raise _fail(code, "service endpoint authority is not canonical")
    path = parsed.path or "/"
    if (
        parsed.path != path
        or not path.startswith("/")
        or posixpath.normpath(path) != path
        or (path != "/" and path.endswith("/"))
    ):
        raise _fail(code, "service endpoint path is not canonical")


def _payload_json(graph: EvidenceGraph, node: Mapping[str, Any], *, label: str) -> Mapping[str, Any]:
    code = "SERVICE_CUSTODY_EVIDENCE_INCOMPLETE"
    digest = node["payload_sha256"]
    if digest is None or digest not in graph.payloads:
        raise _fail(code, f"{label} lacks manifested payload bytes")
    try:
        value = canonical_json_loads(graph.payloads[digest])
    except Exception as exc:
        raise _fail(code, f"{label} payload is not canonical JSON") from exc
    if type(value) is not dict or canonical_json_bytes(value) != graph.payloads[digest]:
        raise _fail(code, f"{label} payload is not a canonical JSON object")
    return value


def _require_contains_edges(
    graph: EvidenceGraph,
    node: Mapping[str, Any],
    *,
    code: str,
    label: str,
) -> None:
    edges = [edge for edge in graph.edges if edge["from_node_id"] == node["node_id"]]
    children = node["child_node_ids"]
    if (
        len(edges) != len(children)
        or {edge["to_node_id"] for edge in edges} != set(children)
        or any(edge["relation"] != "CONTAINS" for edge in edges)
    ):
        raise _fail(code, f"{label} must bind every child through exactly one CONTAINS edge")


def _source_artifact(
    graph: EvidenceGraph,
    node_id: str,
    *,
    service_id: str,
    evidence_kind: str,
    code: str,
) -> tuple[Mapping[str, Any], bytes]:
    node = require_root(
        graph,
        node_id,
        frozenset({"CUSTODY_SOURCE_ARTIFACT"}),
        label=f"{evidence_kind} source artifact",
    )
    if node["child_node_ids"] or node["metadata"] != {}:
        raise _fail(code, f"{evidence_kind} source artifact must be a leaf with empty metadata")
    payload = _exact(
        _payload_json(graph, node, label=f"{evidence_kind} source artifact"),
        frozenset(
            {
                "schema",
                "service_id",
                "evidence_kind",
                "media_type",
                "document_base64",
                "document_sha256",
            }
        ),
        f"{evidence_kind} source artifact",
        code=code,
    )
    if (
        payload["schema"] != CUSTODY_SOURCE_ARTIFACT_SCHEMA
        or payload["service_id"] != service_id
        or payload["evidence_kind"] != evidence_kind
    ):
        raise _fail(code, f"{evidence_kind} source artifact does not bind the service and kind")
    _identifier(payload["media_type"], f"{evidence_kind} media type", code=code)
    try:
        document = base64.b64decode(payload["document_base64"], validate=True)
    except Exception as exc:
        raise _fail(code, f"{evidence_kind} source document is not canonical base64") from exc
    if (
        not document
        or base64.b64encode(document).decode("ascii") != payload["document_base64"]
        or hashlib.sha256(document).hexdigest()
        != _sha(payload["document_sha256"], f"{evidence_kind} document", code=code)
    ):
        raise _fail(code, f"{evidence_kind} source document digest or encoding is invalid")
    return payload, document


def _validate_custody_evidence(graph: EvidenceGraph, record: Mapping[str, Any]) -> None:
    code = "SERVICE_CUSTODY_EVIDENCE_INCOMPLETE"
    root = require_root(
        graph,
        record["custody_evidence_root_sha256"],
        frozenset({"SERVICE_CUSTODY_ROOT"}),
        label="service custody root",
    )
    if root["metadata"] != {"service_id": record["service_id"]}:
        raise _fail(code, "service custody root metadata does not bind the service record")
    _require_contains_edges(graph, root, code=code, label="service custody root")
    children = [graph.nodes[child] for child in root["child_node_ids"]]
    child_types = {child["node_type"] for child in children}
    required = set(_CUSTODY_CHILD_TYPES)
    if record["role"] != ROLE_RUNTIME_CUSTODIAN:
        required.add("SIGNING_KEY_CUSTODY_EVIDENCE")
    if child_types != required or len(children) != len(required):
        raise _fail(code, f"service custody root child types must exactly be {sorted(required)}")
    for child in children:
        payload = _payload_json(graph, child, label=child["node_type"])
        if child["node_type"] == "ENDPOINT_PIN_EVIDENCE":
            continue
        evidence_payload = _exact(
            payload,
            frozenset(
                {
                    "schema",
                    "service_id",
                    "evidence_kind",
                    "artifact_node_id",
                }
            ),
            child["node_type"],
            code=code,
        )
        if (
            evidence_payload["schema"] != SERVICE_CUSTODY_EVIDENCE_SCHEMA
            or evidence_payload["service_id"] != record["service_id"]
            or evidence_payload["evidence_kind"] != child["node_type"]
        ):
            raise _fail(code, f"{child['node_type']} does not bind the reviewed service")
        artifact_node_id = _sha(
            evidence_payload["artifact_node_id"],
            f"{child['node_type']} artifact node",
            code=code,
        )
        if child["child_node_ids"] != [artifact_node_id]:
            raise _fail(code, f"{child['node_type']} must contain its exact source artifact")
        _require_contains_edges(graph, child, code=code, label=child["node_type"])
        _source_artifact(
            graph,
            artifact_node_id,
            service_id=record["service_id"],
            evidence_kind=child["node_type"],
            code=code,
        )
    endpoint_node = next(child for child in children if child["node_type"] == "ENDPOINT_PIN_EVIDENCE")
    endpoint_payload = _exact(
        _payload_json(graph, endpoint_node, label="endpoint pin evidence"),
        frozenset(
            {
                "schema",
                "service_id",
                "endpoint_uri",
                "endpoint_pin_sha256",
                "certificate_or_key_artifact_node_id",
            }
        ),
        "endpoint pin evidence",
        code=code,
    )
    if (
        endpoint_payload["schema"] != ENDPOINT_PIN_EVIDENCE_SCHEMA
        or endpoint_payload["service_id"] != record["service_id"]
        or endpoint_payload["endpoint_uri"] != record["endpoint_uri"]
        or endpoint_payload["endpoint_pin_sha256"] != record["endpoint_pin_sha256"]
    ):
        raise _fail(code, "endpoint pin evidence does not bind the service record")
    endpoint_artifact_node_id = _sha(
        endpoint_payload["certificate_or_key_artifact_node_id"],
        "endpoint certificate or key artifact node",
        code=code,
    )
    if endpoint_node["child_node_ids"] != [endpoint_artifact_node_id]:
        raise _fail(code, "endpoint pin evidence must contain its exact certificate or key artifact")
    _require_contains_edges(graph, endpoint_node, code=code, label="endpoint pin evidence")
    endpoint_artifact, _ = _source_artifact(
        graph,
        endpoint_artifact_node_id,
        service_id=record["service_id"],
        evidence_kind="ENDPOINT_PIN_EVIDENCE",
        code=code,
    )
    if endpoint_artifact["document_sha256"] != record["endpoint_pin_sha256"]:
        raise _fail(code, "endpoint pin does not match the closed certificate or key artifact")
    runtime = require_root(
        graph,
        record["service_runtime_manifest_root_sha256"],
        frozenset({"SERVICE_RUNTIME_MANIFEST"}),
        label="service runtime manifest root",
    )
    runtime_payload = _exact(
        _payload_json(graph, runtime, label="service runtime manifest"),
        frozenset(
            {
                "schema",
                "service_id",
                "source_revision_sha256",
                "build_manifest_sha256",
                "deployment_manifest_sha256",
                "runtime_configuration_sha256",
            }
        ),
        "service runtime manifest",
        code=code,
    )
    if (
        runtime_payload["schema"] != SERVICE_RUNTIME_MANIFEST_SCHEMA
        or runtime_payload["service_id"] != record["service_id"]
    ):
        raise _fail(code, "service runtime manifest does not bind the reviewed service")
    runtime_artifacts = {
        "SERVICE_SOURCE_REVISION": "source_revision_sha256",
        "SERVICE_BUILD_MANIFEST": "build_manifest_sha256",
        "SERVICE_DEPLOYMENT_MANIFEST": "deployment_manifest_sha256",
        "SERVICE_RUNTIME_CONFIGURATION": "runtime_configuration_sha256",
    }
    if len(runtime["child_node_ids"]) != len(runtime_artifacts):
        raise _fail(code, "service runtime manifest must contain four exact source artifacts")
    _require_contains_edges(graph, runtime, code=code, label="service runtime manifest")
    seen_runtime_kinds: set[str] = set()
    for artifact_node_id in runtime["child_node_ids"]:
        artifact_node = require_root(
            graph,
            artifact_node_id,
            frozenset({"CUSTODY_SOURCE_ARTIFACT"}),
            label="service runtime source artifact",
        )
        artifact_payload = _payload_json(
            graph, artifact_node, label="service runtime source artifact"
        )
        evidence_kind = artifact_payload.get("evidence_kind")
        if evidence_kind not in runtime_artifacts or evidence_kind in seen_runtime_kinds:
            raise _fail(code, "service runtime source artifact kinds are incomplete or duplicated")
        seen_runtime_kinds.add(evidence_kind)
        source_payload, _ = _source_artifact(
            graph,
            artifact_node_id,
            service_id=record["service_id"],
            evidence_kind=evidence_kind,
            code=code,
        )
        field = runtime_artifacts[evidence_kind]
        if source_payload["document_sha256"] != _sha(
            runtime_payload[field], f"service runtime {field}", code=code
        ):
            raise _fail(code, f"service runtime {field} does not match its closed artifact")


_REVIEWER_IDENTITY_FIELDS = frozenset(
    {
        "schema",
        "candidate_trust_policy_sha256",
        "reviewer_key_id",
        "reviewer_subject_id",
        "reviewer_control_group_id",
        "reviewer_organization_id",
        "issuer_key_id",
        "identity_artifact_node_id",
        "issued_at_utc",
    }
)


def _verify_reviewer_identities(
    values: Any,
    *,
    reviewers: Mapping[str, Mapping[str, Any]],
    identity_issuers: Mapping[str, Mapping[str, Any]],
    graph: EvidenceGraph,
    policy_sha256: str,
) -> None:
    code = "CUSTODY_SEPARATION_INVALID"
    if type(values) is not list or len(values) != len(reviewers):
        raise _fail(code, "every custody reviewer requires one issuer-signed identity binding")
    expected_order = sorted(reviewers)
    if [item.get("reviewer_key_id") for item in values if type(item) is dict] != expected_order:
        raise _fail(code, "custody reviewer identity roots must be sorted by reviewer_key_id")
    used_issuers: set[str] = set()
    for index, item in enumerate(values):
        binding = _exact(
            item,
            frozenset({"reviewer_key_id", "identity_root_sha256"}),
            f"custody reviewer identity root[{index}]",
            code=code,
        )
        reviewer_key_id = _identifier(
            binding["reviewer_key_id"], "custody reviewer identity key", code=code
        )
        reviewer = reviewers.get(reviewer_key_id)
        if reviewer is None:
            raise _fail(code, "custody reviewer identity root references an unknown reviewer")
        root = require_root(
            graph,
            binding["identity_root_sha256"],
            frozenset({"CUSTODY_REVIEWER_IDENTITY_BINDING"}),
            label="custody reviewer identity binding",
        )
        if root["metadata"] != {"reviewer_key_id": reviewer_key_id}:
            raise _fail(code, "custody reviewer identity root metadata mismatch")
        envelope = _exact(
            _payload_json(graph, root, label="custody reviewer identity binding"),
            frozenset({"schema", "payload", "signature_base64"}),
            "custody reviewer identity envelope",
            code=code,
        )
        if envelope["schema"] != CUSTODY_REVIEWER_IDENTITY_ENVELOPE_SCHEMA:
            raise _fail(code, "custody reviewer identity envelope schema mismatch")
        payload = _exact(
            envelope["payload"],
            _REVIEWER_IDENTITY_FIELDS,
            "custody reviewer identity payload",
            code=code,
        )
        issuer_key_id = _identifier(payload["issuer_key_id"], "identity issuer key", code=code)
        issuer = identity_issuers.get(issuer_key_id)
        if issuer is None:
            raise _fail(code, "custody reviewer identity signer is not a candidate-policy issuer")
        if (
            payload["schema"] != CUSTODY_REVIEWER_IDENTITY_SCHEMA
            or payload["candidate_trust_policy_sha256"] != policy_sha256
            or payload["reviewer_key_id"] != reviewer_key_id
            or payload["reviewer_subject_id"] != reviewer["subject_id"]
            or payload["reviewer_control_group_id"] != reviewer["control_group_id"]
            or payload["reviewer_organization_id"] != reviewer["organization_id"]
        ):
            raise _fail(code, "custody reviewer identity payload does not bind the reviewer")
        _utc(payload["issued_at_utc"], "custody reviewer identity issued_at", code=code)
        artifact_node_id = _sha(
            payload["identity_artifact_node_id"],
            "custody reviewer identity artifact node",
            code=code,
        )
        if root["child_node_ids"] != [artifact_node_id]:
            raise _fail(code, "custody reviewer identity root must contain its exact source artifact")
        _require_contains_edges(graph, root, code=code, label="custody reviewer identity root")
        _source_artifact(
            graph,
            artifact_node_id,
            service_id=f"reviewer:{reviewer_key_id}",
            evidence_kind="CUSTODY_REVIEWER_IDENTITY",
            code=code,
        )
        try:
            signature = base64.b64decode(envelope["signature_base64"], validate=True)
        except Exception as exc:
            raise _fail(code, "custody reviewer identity signature is not canonical base64") from exc
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != envelope["signature_base64"]:
            raise _fail(code, "custody reviewer identity signature encoding is invalid")
        message = DOMAIN_CUSTODY_REVIEWER_IDENTITY + hashlib.sha256(
            canonical_json_bytes(payload)
        ).digest()
        try:
            Ed25519PublicKey.from_public_bytes(issuer["public_key"]).verify(signature, message)
        except InvalidSignature as exc:
            raise _fail(code, "custody reviewer identity signature is invalid") from exc
        used_issuers.add(issuer_key_id)
    if used_issuers != set(identity_issuers):
        raise _fail(code, "custody reviewer identities must collectively use both identity issuers")


_REVIEW_FIELDS = frozenset(
    {
        "schema",
        "candidate_trust_policy_sha256",
        "evidence_graph_root_sha256",
        "service_record_sha256",
        "reviewer_key_id",
        "reviewer_subject_id",
        "reviewer_control_group_id",
        "reviewer_organization_id",
        "review_challenge_sha256",
        "reviewed_at_utc",
        "verdict",
        "findings_root_sha256",
    }
)


def _verify_reviews(
    values: Any,
    *,
    records: Mapping[str, Mapping[str, Any]],
    reviewers: Mapping[str, Mapping[str, Any]],
    graph: EvidenceGraph,
    policy_sha256: str,
    graph_root_sha256: str,
    review_challenge_sha256: str,
) -> None:
    code = "CUSTODY_REVIEW_QUORUM_INVALID"
    if type(values) is not list:
        raise _fail(code, "custody reviews must be a list")
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    previous_sort_key: tuple[str, str] | None = None
    for index, raw in enumerate(values):
        envelope = _exact(
            raw,
            frozenset({"schema", "payload", "signature_base64"}),
            f"custody review envelope[{index}]",
            code=code,
        )
        if envelope["schema"] != CUSTODY_REVIEW_ENVELOPE_SCHEMA:
            raise _fail(code, "custody review envelope schema mismatch")
        payload = _exact(envelope["payload"], _REVIEW_FIELDS, f"custody review[{index}]", code=code)
        if (
            payload["schema"] != CUSTODY_REVIEW_SCHEMA
            or payload["candidate_trust_policy_sha256"] != policy_sha256
            or payload["evidence_graph_root_sha256"] != graph_root_sha256
            or payload["review_challenge_sha256"] != review_challenge_sha256
            or payload["verdict"] != "PASS"
        ):
            raise _fail(code, "custody review does not bind the candidate policy, graph, and PASS verdict")
        service_sha = _sha(payload["service_record_sha256"], "reviewed service record", code=code)
        if service_sha not in records:
            raise _fail(code, "custody review references an unknown service record")
        key_id = _identifier(payload["reviewer_key_id"], "custody reviewer key id", code=code)
        reviewer = reviewers.get(key_id)
        if reviewer is None:
            raise _fail(code, "custody review signer is not in the candidate reviewer set")
        for field, reviewer_field in (
            ("reviewer_subject_id", "subject_id"),
            ("reviewer_control_group_id", "control_group_id"),
            ("reviewer_organization_id", "organization_id"),
        ):
            if payload[field] != reviewer[reviewer_field]:
                raise _fail(code, f"custody review {field} does not match its signer")
        _utc(payload["reviewed_at_utc"], "custody review timestamp", code=code)
        findings = require_root(
            graph,
            payload["findings_root_sha256"],
            frozenset({"CUSTODY_REVIEW_FINDINGS"}),
            label="custody review findings root",
        )
        findings_payload = _exact(
            _payload_json(graph, findings, label="custody review findings"),
            frozenset(
                {
                    "schema",
                    "service_record_sha256",
                    "reviewer_key_id",
                    "verdict",
                    "findings",
                }
            ),
            "custody review findings",
            code=code,
        )
        if (
            findings_payload["schema"] != CUSTODY_REVIEW_FINDINGS_SCHEMA
            or findings_payload["service_record_sha256"] != service_sha
            or findings_payload["reviewer_key_id"] != key_id
            or findings_payload["verdict"] != "PASS"
            or findings_payload["findings"] != []
        ):
            raise _fail(code, "custody review findings do not bind a clean PASS for the service and reviewer")
        sort_key = (service_sha, key_id)
        if previous_sort_key is not None and sort_key <= previous_sort_key:
            raise _fail(code, "custody reviews must be strictly sorted by service and reviewer")
        previous_sort_key = sort_key
        if sort_key in seen:
            raise _fail(code, "duplicate custody review")
        seen.add(sort_key)
        try:
            signature = base64.b64decode(envelope["signature_base64"], validate=True)
        except Exception as exc:
            raise _fail(code, "custody review signature is not canonical base64") from exc
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != envelope["signature_base64"]:
            raise _fail(code, "custody review signature encoding is invalid")
        message = DOMAIN_CUSTODY_REVIEW + hashlib.sha256(canonical_json_bytes(payload)).digest()
        try:
            Ed25519PublicKey.from_public_bytes(reviewer["public_key"]).verify(signature, message)
        except InvalidSignature as exc:
            raise _fail(code, "custody review signature is invalid") from exc
        grouped[service_sha].append(reviewer)
    if set(grouped) != set(records):
        raise _fail(code, "every service record requires a custody review quorum")
    for service_sha, service_reviewers in grouped.items():
        if len(service_reviewers) != 2:
            raise _fail(code, "each service record requires exactly two custody reviews")
        service = records[service_sha]
        if len({item["control_group_id"] for item in service_reviewers}) != 2 or len({item["organization_id"] for item in service_reviewers}) != 2:
            raise _fail(code, "custody review quorum lacks independent control groups or organizations")
        if any(
            item["control_group_id"] == service["control_group_id"]
            or item["organization_id"] == service["organization_id"]
            for item in service_reviewers
        ):
            raise _fail("CUSTODY_SEPARATION_INVALID", "service custody reviewer aliases the reviewed service")


_PACKET_FIELDS = frozenset(
    {
        "schema",
        "candidate_trust_policy_sha256",
        "evidence_graph_root_sha256",
        "custody_reviewer_authorities",
        "custody_reviewer_identity_root_sha256s",
        "custody_reviewer_quorum",
        "review_challenge_sha256",
        "service_records",
        "custody_review_envelopes",
    }
)


def verify_external_provisioning_readiness(
    *,
    candidate_trust_policy: Mapping[str, Any],
    candidate_trust_policy_sha256: str,
    provisioning_packet: Mapping[str, Any],
    nodes_jsonl: bytes,
    edges_jsonl: bytes,
    payload_manifest_jsonl: bytes,
    payloads: Mapping[str, bytes],
) -> dict[str, Any]:
    policy = validate_trust_policy(
        candidate_trust_policy,
        expected_sha256=candidate_trust_policy_sha256,
    )
    packet = _exact(
        provisioning_packet,
        _PACKET_FIELDS,
        "external provisioning packet",
        code="PROVISIONING_PACKET_INVALID",
    )
    if (
        packet["schema"] != PROVISIONING_PACKET_SCHEMA
        or packet["candidate_trust_policy_sha256"] != candidate_trust_policy_sha256
        or packet["custody_reviewer_quorum"] != "2"
    ):
        raise _fail("PROVISIONING_PACKET_INVALID", "provisioning packet schema, policy, or quorum mismatch")
    review_challenge = _sha(
        packet["review_challenge_sha256"],
        "custody review challenge",
        code="PROVISIONING_PACKET_INVALID",
    )
    graph_root = _sha(
        packet["evidence_graph_root_sha256"],
        "provisioning evidence graph root",
        code="PROVISIONING_PACKET_INVALID",
    )
    try:
        graph = validate_evidence_graph(
            nodes_jsonl=nodes_jsonl,
            edges_jsonl=edges_jsonl,
            payload_manifest_jsonl=payload_manifest_jsonl,
            payloads=payloads,
            expected_root_sha256=graph_root,
            expected_policy_sha256=policy["evidence_policy_sha256"],
        )
    except Exception as exc:
        code = getattr(exc, "code", "EVIDENCE_GRAPH_HASH_MISMATCH")
        if code not in PROVISIONING_FAILURE_STATES:
            code = "EVIDENCE_GRAPH_HASH_MISMATCH"
        raise _fail(code, str(exc)) from exc
    reviewers = _reviewers(packet["custody_reviewer_authorities"])
    authorities = _policy_authorities(policy)
    if set(reviewers) & set(authorities):
        raise _fail("CUSTODY_SEPARATION_INVALID", "custody reviewer keys alias trust-authority keys")
    _verify_reviewer_identities(
        packet["custody_reviewer_identity_root_sha256s"],
        reviewers=reviewers,
        identity_issuers=policy["identity_issuers"],
        graph=graph,
        policy_sha256=candidate_trust_policy_sha256,
    )
    records_raw = packet["service_records"]
    if type(records_raw) is not list:
        raise _fail("PROVISIONING_PACKET_INVALID", "service_records must be a list")
    records = [_service_record(value, index) for index, value in enumerate(records_raw)]
    if [record["service_id"] for record in records] != sorted(record["service_id"] for record in records):
        raise _fail("PROVISIONING_PACKET_INVALID", "service records must be sorted by service_id")
    if len({record["service_id"] for record in records}) != len(records):
        raise _fail("PROVISIONING_PACKET_INVALID", "service ids must be unique")
    counts = Counter(record["role"] for record in records)
    if dict(counts) != _EXPECTED_ROLE_COUNTS:
        raise _fail("SERVICE_ROSTER_INCOMPLETE", f"service role counts must exactly be {_EXPECTED_ROLE_COUNTS}")
    authority_subjects = {authority["subject_id"] for authority in authorities.values()}
    authority_controls = {authority["control_group_id"] for authority in authorities.values()}
    authority_orgs = {authority["organization_id"] for authority in authorities.values()}
    for record in records:
        if record["role"] == ROLE_RUNTIME_CUSTODIAN:
            if (
                record["control_group_id"] in set(policy["project_control_group_ids"])
                or record["subject_id"] in authority_subjects
                or record["control_group_id"] in authority_controls
                or record["organization_id"] in authority_orgs
            ):
                raise _fail("CUSTODY_SEPARATION_INVALID", "runtime custodian aliases project or trust-authority custody")
        else:
            authority = authorities.get(record["authority_key_id"])
            if authority is None or any(
                record[field] != authority[field]
                for field in ("role", "subject_id", "control_group_id", "organization_id")
            ):
                raise _fail("SERVICE_POLICY_MISMATCH", "service record does not match a candidate-policy authority")
        _validate_custody_evidence(graph, record)
    for field in ("subject_id", "control_group_id", "organization_id", "endpoint_uri"):
        if len({record[field] for record in records}) != len(records):
            raise _fail("CUSTODY_SEPARATION_INVALID", f"service records must have distinct {field} values")
    service_controls = {record["control_group_id"] for record in records}
    service_orgs = {record["organization_id"] for record in records}
    reviewer_controls = {reviewer["control_group_id"] for reviewer in reviewers.values()}
    reviewer_orgs = {reviewer["organization_id"] for reviewer in reviewers.values()}
    if service_controls & reviewer_controls or service_orgs & reviewer_orgs:
        raise _fail("CUSTODY_SEPARATION_INVALID", "custody reviewers alias service controls or organizations")
    if set(policy["project_control_group_ids"]) & reviewer_controls:
        raise _fail("CUSTODY_SEPARATION_INVALID", "custody reviewer aliases project control")
    if (
        authority_controls & reviewer_controls
        or authority_orgs & reviewer_orgs
        or authority_subjects & {reviewer["subject_id"] for reviewer in reviewers.values()}
    ):
        raise _fail("CUSTODY_SEPARATION_INVALID", "custody reviewer aliases trust-authority custody")
    by_sha = {record["sha256"]: record for record in records}
    _verify_reviews(
        packet["custody_review_envelopes"],
        records=by_sha,
        reviewers=reviewers,
        graph=graph,
        policy_sha256=candidate_trust_policy_sha256,
        graph_root_sha256=graph_root,
        review_challenge_sha256=review_challenge,
    )
    return {
        "schema": PROVISIONING_VERDICT_SCHEMA,
        "state": "CANDIDATE_EXTERNAL_SERVICES_PACKET_STRUCTURALLY_COMPLETE_REQUIRES_LIVE_CHALLENGE_AND_POLICY_PIN_REVIEW",
        "candidate_trust_policy_sha256": candidate_trust_policy_sha256,
        "evidence_graph_root_sha256": graph_root,
        "provisioning_packet_sha256": canonical_sha256(packet),
        "custody_reviewer_authorities_root_sha256": canonical_sha256(
            packet["custody_reviewer_authorities"]
        ),
        "service_records_root_sha256": canonical_sha256([record["raw"] for record in records]),
        "custody_reviews_root_sha256": canonical_sha256(packet["custody_review_envelopes"]),
        "service_count": len(records),
        "provisioning_evidence_complete": False,
        "offline_packet_structurally_complete": True,
        "underlying_custody_artifacts_closed": True,
        "reviewer_identity_bindings_verified_against_candidate_issuers": True,
        "review_challenge_external_issuance_verified": False,
        "review_challenge_single_use_verified": False,
        "candidate_policy_ready_for_independent_review": True,
        "candidate_policy_pinned": False,
        "external_authentication_verified": False,
        "population_feasible": False,
        "recruitment_intake_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "permits": [],
        "sealed_holdout_accessed": False,
        "local_process_output_authoritative": False,
    }


def fail_closed_provisioning_verdict(state: str, reason: str) -> dict[str, Any]:
    if state not in PROVISIONING_FAILURE_STATES:
        reason = f"invalid failure state {state!r}: {reason}"
        state = "PROVISIONING_PACKET_INVALID"
    return {
        "schema": PROVISIONING_VERDICT_SCHEMA,
        "state": state,
        "reason": reason,
        "provisioning_evidence_complete": False,
        "offline_packet_structurally_complete": False,
        "underlying_custody_artifacts_closed": False,
        "reviewer_identity_bindings_verified_against_candidate_issuers": False,
        "review_challenge_external_issuance_verified": False,
        "review_challenge_single_use_verified": False,
        "candidate_policy_ready_for_independent_review": False,
        "candidate_policy_pinned": False,
        "external_authentication_verified": False,
        "population_feasible": False,
        "recruitment_intake_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "permits": [],
        "sealed_holdout_accessed": False,
        "local_process_output_authoritative": False,
    }


def assess_external_provisioning_readiness(**kwargs: Any) -> dict[str, Any]:
    try:
        return verify_external_provisioning_readiness(**kwargs)
    except ProvisioningV626Error as exc:
        return fail_closed_provisioning_verdict(exc.code, str(exc))
    except Exception as exc:
        return fail_closed_provisioning_verdict(
            "PROVISIONING_PACKET_INVALID",
            f"unexpected provisioning verifier failure: {type(exc).__name__}: {exc}",
        )


def current_external_provisioning_status() -> dict[str, Any]:
    return fail_closed_provisioning_verdict(
        "EXTERNAL_PROVISIONING_EVIDENCE_ABSENT",
        "no independently reviewed external service custody packet is present",
    )


__all__ = [
    "CUSTODY_REVIEW_ENVELOPE_SCHEMA",
    "CUSTODY_REVIEW_FINDINGS_SCHEMA",
    "CUSTODY_REVIEWER_IDENTITY_ENVELOPE_SCHEMA",
    "CUSTODY_REVIEWER_IDENTITY_SCHEMA",
    "CUSTODY_REVIEW_SCHEMA",
    "CUSTODY_SOURCE_ARTIFACT_SCHEMA",
    "DOMAIN_CUSTODY_REVIEW",
    "DOMAIN_CUSTODY_REVIEWER_IDENTITY",
    "ENDPOINT_PIN_EVIDENCE_SCHEMA",
    "PROVISIONING_FAILURE_STATES",
    "PROVISIONING_PACKET_SCHEMA",
    "PROVISIONING_VERDICT_SCHEMA",
    "ProvisioningV626Error",
    "ROLE_CUSTODY_REVIEWER",
    "ROLE_RUNTIME_CUSTODIAN",
    "SERVICE_CUSTODY_EVIDENCE_SCHEMA",
    "SERVICE_RECORD_SCHEMA",
    "SERVICE_RUNTIME_MANIFEST_SCHEMA",
    "assess_external_provisioning_readiness",
    "current_external_provisioning_status",
    "fail_closed_provisioning_verdict",
    "verify_external_provisioning_readiness",
]
