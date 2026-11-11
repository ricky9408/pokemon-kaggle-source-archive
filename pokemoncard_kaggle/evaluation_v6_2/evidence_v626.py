"""Closed evidence-graph and runtime-TCB validation for v6.2.6."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import re
from typing import Any

from .integration_v622 import canonical_json_bytes, canonical_json_loads


EVIDENCE_NODE_SCHEMA = "eval.v6.2.6.evidence-node"
EVIDENCE_EDGE_SCHEMA = "eval.v6.2.6.evidence-edge"
EVIDENCE_PAYLOAD_SCHEMA = "eval.v6.2.6.evidence-payload"
RUNTIME_MANIFEST_SCHEMA = "eval.v6.2.6.runtime-manifest"
EXECUTION_TRANSCRIPT_SCHEMA = "eval.v6.2.6.execution-transcript"

DOMAIN_EVIDENCE_NODE = b"EVAL-V626/EVIDENCE-NODE\0"
DOMAIN_EVIDENCE_GRAPH = b"EVAL-V626/EVIDENCE-GRAPH\0"

EVIDENCE_FAILURE_STATES = frozenset(
    {
        "EVIDENCE_GRAPH_DANGLING",
        "EVIDENCE_GRAPH_HASH_MISMATCH",
        "EVIDENCE_GRAPH_TYPE_INVALID",
        "EVIDENCE_GRAPH_PROHIBITED_CYCLE",
        "PRINCIPAL_IDENTITY_EVIDENCE_INSUFFICIENT",
        "PAIR_ANALYSIS_EVIDENCE_INCOMPLETE",
        "VERIFIER_TCB_MANIFEST_INCOMPLETE",
        "VERIFIER_TCB_MISMATCH",
        "COMPONENT_DERIVATION_CIRCULAR",
        "COMPONENT_ID_RECOMPUTATION_MISMATCH",
        "DERIVATION_STAGE_VIOLATION",
    }
)

NODE_TYPES = frozenset(
    {
        "POPULATION_ANALYSIS_ROOT",
        "EVIDENCE_INPUT_GRAPH_ROOT",
        "PAIR_CLASSIFICATION_GRAPH_ROOT",
        "COMPONENT_ASSIGNMENT_ROOT",
        "COMPONENT_ASSIGNMENT",
        "POPULATION_DECISION_ROOT",
        "PAIR_ANALYSIS_ROOT",
        "PAIR_STATE_DERIVATION",
        "LINEAGE_RECEIPT",
        "INTERVENTION_RECEIPT",
        "SOURCE_SIMILARITY_INPUT",
        "SOURCE_SIMILARITY_OUTPUT",
        "VCS_PROVENANCE_INPUT",
        "EXPOSURE_FEEDBACK_EVIDENCE",
        "REVIEWER_IDENTITY_BINDING",
        "ANALYSIS_TOOL",
        "POLICY_ARTIFACT",
        "PRINCIPAL_ASSIGNMENT",
        "IDENTITY_BINDING",
        "REGISTRY_RECORD",
        "UNDERLYING_IDENTITY_EVIDENCE",
        "ISSUER_AUTHORITY_RECEIPT",
        "RUNTIME_MANIFEST",
        "PYTHON_MODULE_MANIFEST",
        "NATIVE_LIBRARY_MANIFEST",
        "CRYPTO_LIBRARY_MANIFEST",
        "POLICY_CONFIG_MANIFEST",
        "ENVIRONMENT_ALLOWLIST",
        "NETWORK_ENDPOINT_POLICY",
        "EXECUTION_TRANSCRIPT",
        "ENVIRONMENT_ATTESTATION",
        "COMPREHENSIVE_VERIFIER_RECEIPT",
        "CAMPAIGN_BUNDLE",
        "VERIFICATION_PACKET",
        "SERVICE_CUSTODY_ROOT",
        "SIGNING_KEY_CUSTODY_EVIDENCE",
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
        "CUSTODY_SOURCE_ARTIFACT",
        "CUSTODY_REVIEWER_IDENTITY_BINDING",
        "SERVICE_RUNTIME_MANIFEST",
        "CUSTODY_REVIEW_FINDINGS",
    }
)

EDGE_RELATIONS = frozenset(
    {
        "CONTAINS",
        "DERIVES_FROM",
        "BINDS",
        "ATTESTS",
        "VALIDATES",
        "PRODUCED_BY",
    }
)

PAIR_REQUIRED_CHILD_TYPES = frozenset(
    {
        "LINEAGE_RECEIPT",
        "INTERVENTION_RECEIPT",
        "SOURCE_SIMILARITY_INPUT",
        "SOURCE_SIMILARITY_OUTPUT",
        "VCS_PROVENANCE_INPUT",
        "EXPOSURE_FEEDBACK_EVIDENCE",
        "REVIEWER_IDENTITY_BINDING",
        "ANALYSIS_TOOL",
        "POLICY_ARTIFACT",
        "PAIR_STATE_DERIVATION",
    }
)

REQUIRED_TRANSCRIPT_EVENTS = (
    "SESSION_INITIALIZATION",
    "CHALLENGE_VALIDATION",
    "RUNTIME_MANIFEST_VERIFICATION",
    "EVIDENCE_GRAPH_VERIFICATION",
    "SEMANTIC_CHECKS_COMPLETE",
    "WITNESS_STATE_QUERY",
    "OUTPUT_CHECK_VECTOR",
    "SESSION_CLOSURE",
)

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32,256}$")
_CONTAINER_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMPONENT_ID_RE = re.compile(r"^(sf|lt|if)-[0-9a-f]{24}$")
_COMPONENT_PREFIX = {
    "SOURCE_FAMILY": "sf",
    "LINEAGE_TIME": "lt",
    "INTERVENTION_FAMILY": "if",
}


class EvidenceV626Error(ValueError):
    """A canonical evidence-graph invariant failed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in EVIDENCE_FAILURE_STATES:
            raise ValueError(f"unknown v6.2.6 evidence failure state: {code}")
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class EvidenceGraph:
    root_sha256: str
    nodes: Mapping[str, Mapping[str, Any]]
    edges: tuple[Mapping[str, Any], ...]
    payloads: Mapping[str, bytes]


@dataclass(frozen=True)
class RuntimeManifest:
    node_id: str
    runtime_custodian_subject_id: str
    runtime_custodian_control_group_id: str
    runtime_custodian_organization_id: str
    accepted_verifier_build_root_sha256: str
    runtime_tcb_policy_sha256: str


@dataclass(frozen=True)
class ExecutionTranscript:
    node_id: str
    session_id: str
    authority_challenge: str
    verification_nonce: str
    runtime_manifest_root_sha256: str
    event_types: tuple[str, ...]


def _fail(code: str, message: str) -> EvidenceV626Error:
    return EvidenceV626Error(code, message)


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


def _nonce(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or _NONCE_RE.fullmatch(value) is None or len(value) % 2:
        raise _fail(code, f"{label} must be 16 through 128 bytes of lowercase hex")
    return value


def _decimal(value: Any, label: str, *, code: str) -> int:
    if type(value) is not str or not value.isdigit() or (len(value) > 1 and value[0] == "0"):
        raise _fail(code, f"{label} must be a canonical nonnegative decimal string")
    return int(value)


def evidence_node_id(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload.pop("node_id", None)
    return hashlib.sha256(DOMAIN_EVIDENCE_NODE + canonical_json_bytes(payload)).hexdigest()


def _canonical_jsonl(data: bytes, *, label: str, code: str) -> list[Mapping[str, Any]]:
    if not data or not data.endswith(b"\n") or b"\r" in data:
        raise _fail(code, f"{label} must be nonempty canonical LF-terminated JSONL")
    lines = data[:-1].split(b"\n")
    if any(not line for line in lines):
        raise _fail(code, f"{label} contains an empty line")
    values: list[Mapping[str, Any]] = []
    for index, line in enumerate(lines):
        try:
            value = canonical_json_loads(line)
        except Exception as exc:
            raise _fail(code, f"{label}[{index}] is not canonical JSON") from exc
        if type(value) is not dict or canonical_json_bytes(value) != line:
            raise _fail(code, f"{label}[{index}] is not a canonical JSON object")
        values.append(value)
    return values


def _validate_payload_manifest(
    values: Sequence[Mapping[str, Any]],
    payloads: Mapping[str, bytes],
) -> dict[str, bytes]:
    code = "EVIDENCE_GRAPH_HASH_MISMATCH"
    if list(values) != sorted(values, key=lambda item: item.get("payload_sha256", "")):
        raise _fail(code, "evidence payload manifest must be sorted by payload_sha256")
    declared: dict[str, bytes] = {}
    for index, value in enumerate(values):
        item = _exact(
            value,
            frozenset({"schema", "payload_sha256", "payload_byte_length", "media_type"}),
            f"payload manifest[{index}]",
            code=code,
        )
        if item["schema"] != EVIDENCE_PAYLOAD_SCHEMA:
            raise _fail(code, "evidence payload schema mismatch")
        digest = _sha(item["payload_sha256"], "payload digest", code=code)
        if digest in declared:
            raise _fail(code, "duplicate payload digest")
        length = _decimal(item["payload_byte_length"], "payload byte length", code=code)
        _identifier(item["media_type"], "payload media type", code=code)
        raw = payloads.get(digest)
        if type(raw) is not bytes or len(raw) != length or hashlib.sha256(raw).hexdigest() != digest:
            raise _fail(code, f"payload {digest} is absent or does not match its hash and length")
        declared[digest] = raw
    if set(payloads) != set(declared):
        raise _fail(code, "payload inventory contains undeclared or missing bytes")
    return declared


def _validate_nodes(values: Sequence[Mapping[str, Any]], payloads: Mapping[str, bytes]) -> dict[str, Mapping[str, Any]]:
    code = "EVIDENCE_GRAPH_HASH_MISMATCH"
    if list(values) != sorted(values, key=lambda item: item.get("node_id", "")):
        raise _fail(code, "evidence nodes must be sorted by node_id")
    nodes: dict[str, Mapping[str, Any]] = {}
    fields = frozenset(
        {
            "schema",
            "node_id",
            "node_type",
            "policy_sha256",
            "payload_sha256",
            "payload_byte_length",
            "producer_subject_id",
            "producer_role",
            "slot_id",
            "pair_id",
            "unit_nonce",
            "child_node_ids",
            "metadata",
        }
    )
    for index, value in enumerate(values):
        item = _exact(value, fields, f"evidence node[{index}]", code=code)
        if item["schema"] != EVIDENCE_NODE_SCHEMA:
            raise _fail(code, "evidence node schema mismatch")
        node_id = _sha(item["node_id"], "evidence node id", code=code)
        if node_id in nodes or evidence_node_id(item) != node_id:
            raise _fail(code, "evidence node id is duplicate or not content-derived")
        if item["node_type"] not in NODE_TYPES:
            raise _fail("EVIDENCE_GRAPH_TYPE_INVALID", f"unsupported evidence node type {item['node_type']!r}")
        _sha(item["policy_sha256"], "evidence node policy", code=code)
        payload_sha = item["payload_sha256"]
        payload_length = item["payload_byte_length"]
        if (payload_sha is None) != (payload_length is None):
            raise _fail(code, "payload hash and byte length must both be null or both be present")
        if payload_sha is not None:
            digest = _sha(payload_sha, "node payload digest", code=code)
            length = _decimal(payload_length, "node payload byte length", code=code)
            if digest not in payloads or len(payloads[digest]) != length:
                raise _fail("EVIDENCE_GRAPH_DANGLING", "node payload is not present in the closed manifest")
        for field in ("producer_subject_id", "producer_role", "slot_id", "pair_id"):
            if item[field] is not None:
                _identifier(item[field], f"evidence node {field}", code=code)
        if item["unit_nonce"] is not None:
            _nonce(item["unit_nonce"], "evidence node unit nonce", code=code)
        children = item["child_node_ids"]
        if type(children) is not list or children != sorted(children) or len(children) != len(set(children)):
            raise _fail(code, "child_node_ids must be a sorted unique list")
        for child in children:
            _sha(child, "child node id", code=code)
        if type(item["metadata"]) is not dict:
            raise _fail(code, "evidence node metadata must be an object")
        nodes[node_id] = item
    return nodes


def _validate_edges(values: Sequence[Mapping[str, Any]], nodes: Mapping[str, Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    code = "EVIDENCE_GRAPH_DANGLING"
    sort_key = lambda item: (item.get("from_node_id", ""), item.get("relation", ""), item.get("to_node_id", ""), item.get("policy_clause", ""))
    if list(values) != sorted(values, key=sort_key):
        raise _fail(code, "evidence edges must be canonically sorted")
    seen: set[tuple[str, str, str, str]] = set()
    outgoing: dict[str, set[str]] = defaultdict(set)
    for index, value in enumerate(values):
        item = _exact(
            value,
            frozenset({"schema", "from_node_id", "relation", "to_node_id", "policy_clause"}),
            f"evidence edge[{index}]",
            code=code,
        )
        if item["schema"] != EVIDENCE_EDGE_SCHEMA or item["relation"] not in EDGE_RELATIONS:
            raise _fail("EVIDENCE_GRAPH_TYPE_INVALID", "evidence edge schema or relation is invalid")
        source = _sha(item["from_node_id"], "edge source", code=code)
        target = _sha(item["to_node_id"], "edge target", code=code)
        clause = _identifier(item["policy_clause"], "edge policy clause", code=code)
        if source not in nodes or target not in nodes:
            raise _fail(code, "evidence edge references an absent node")
        key = (source, item["relation"], target, clause)
        if key in seen:
            raise _fail(code, "duplicate evidence edge")
        seen.add(key)
        outgoing[source].add(target)
    for node_id, node in nodes.items():
        if outgoing[node_id] != set(node["child_node_ids"]):
            raise _fail(code, f"node {node_id} child list and graph edges disagree")
    return tuple(values)


def _reject_cycles(nodes: Mapping[str, Mapping[str, Any]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(node_id: str) -> None:
        if node_id in visiting:
            raise _fail("EVIDENCE_GRAPH_PROHIBITED_CYCLE", f"cycle includes node {node_id}")
        if node_id in visited:
            return
        visiting.add(node_id)
        for child in nodes[node_id]["child_node_ids"]:
            if child not in nodes:
                raise _fail("EVIDENCE_GRAPH_DANGLING", f"node {node_id} references absent child {child}")
            walk(child)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in nodes:
        walk(node_id)


def evidence_graph_root(nodes_jsonl: bytes, edges_jsonl: bytes, payload_manifest_jsonl: bytes) -> str:
    return hashlib.sha256(
        DOMAIN_EVIDENCE_GRAPH
        + hashlib.sha256(nodes_jsonl).digest()
        + hashlib.sha256(edges_jsonl).digest()
        + hashlib.sha256(payload_manifest_jsonl).digest()
    ).hexdigest()


def validate_evidence_graph(
    *,
    nodes_jsonl: bytes,
    edges_jsonl: bytes,
    payload_manifest_jsonl: bytes,
    payloads: Mapping[str, bytes],
    expected_root_sha256: str,
    expected_policy_sha256: str,
) -> EvidenceGraph:
    code = "EVIDENCE_GRAPH_HASH_MISMATCH"
    expected_root = _sha(expected_root_sha256, "expected evidence graph root", code=code)
    policy = _sha(expected_policy_sha256, "expected evidence policy", code=code)
    if evidence_graph_root(nodes_jsonl, edges_jsonl, payload_manifest_jsonl) != expected_root:
        raise _fail(code, "joint evidence graph root does not match")
    manifest_values = _canonical_jsonl(payload_manifest_jsonl, label="evidence payload manifest", code=code)
    declared_payloads = _validate_payload_manifest(manifest_values, payloads)
    node_values = _canonical_jsonl(nodes_jsonl, label="evidence nodes", code=code)
    nodes = _validate_nodes(node_values, declared_payloads)
    if any(node["policy_sha256"] != policy for node in nodes.values()):
        raise _fail("EVIDENCE_GRAPH_TYPE_INVALID", "evidence node policy does not match the release-pinned policy")
    edge_values = _canonical_jsonl(edges_jsonl, label="evidence edges", code=code)
    edges = _validate_edges(edge_values, nodes)
    _reject_cycles(nodes)
    return EvidenceGraph(root_sha256=expected_root, nodes=nodes, edges=edges, payloads=declared_payloads)


def require_root(graph: EvidenceGraph, root_sha256: str, allowed_types: frozenset[str], *, label: str) -> Mapping[str, Any]:
    root = _sha(root_sha256, label, code="EVIDENCE_GRAPH_DANGLING")
    node = graph.nodes.get(root)
    if node is None:
        raise _fail("EVIDENCE_GRAPH_DANGLING", f"{label} is absent from the evidence graph")
    if node["node_type"] not in allowed_types:
        raise _fail("EVIDENCE_GRAPH_TYPE_INVALID", f"{label} has type {node['node_type']!r}, expected {sorted(allowed_types)}")
    return node


def validate_pair_analysis(graph: EvidenceGraph, root_sha256: str) -> None:
    node = require_root(graph, root_sha256, frozenset({"PAIR_ANALYSIS_ROOT"}), label="pair analysis root")
    child_types = {graph.nodes[child]["node_type"] for child in node["child_node_ids"]}
    missing = PAIR_REQUIRED_CHILD_TYPES - child_types
    if missing:
        raise _fail("PAIR_ANALYSIS_EVIDENCE_INCOMPLETE", f"pair analysis is missing child types {sorted(missing)}")
    pair_id = node["pair_id"]
    if pair_id is None:
        raise _fail("PAIR_ANALYSIS_EVIDENCE_INCOMPLETE", "pair analysis root lacks pair_id")
    endpoints = node["metadata"].get("endpoint_slot_ids")
    reviewers = node["metadata"].get("required_reviewer_subject_ids")
    if (
        type(endpoints) is not list
        or len(endpoints) != 2
        or endpoints != sorted(endpoints)
        or len(set(endpoints)) != 2
        or type(reviewers) is not list
        or not reviewers
        or reviewers != sorted(reviewers)
        or len(set(reviewers)) != len(reviewers)
    ):
        raise _fail("PAIR_ANALYSIS_EVIDENCE_INCOMPLETE", "pair analysis metadata lacks two endpoints or the required reviewer set")
    lineage_receipts = [
        graph.nodes[child]
        for child in node["child_node_ids"]
        if graph.nodes[child]["node_type"] == "LINEAGE_RECEIPT"
    ]
    if len(lineage_receipts) != 2 or {item["slot_id"] for item in lineage_receipts} != set(endpoints):
        raise _fail("PAIR_ANALYSIS_EVIDENCE_INCOMPLETE", "pair analysis must contain one lineage receipt for each endpoint")
    intervention_reviewers = {
        graph.nodes[child]["producer_subject_id"]
        for child in node["child_node_ids"]
        if graph.nodes[child]["node_type"] == "INTERVENTION_RECEIPT"
    }
    if intervention_reviewers != set(reviewers):
        raise _fail("PAIR_ANALYSIS_EVIDENCE_INCOMPLETE", "pair analysis intervention receipts do not cover the required reviewer set")
    for child_id in node["child_node_ids"]:
        child = graph.nodes[child_id]
        if child["pair_id"] not in (None, pair_id):
            raise _fail("PAIR_ANALYSIS_EVIDENCE_INCOMPLETE", "pair analysis child is bound to another pair")


def validate_principal_assignment(
    graph: EvidenceGraph,
    root_sha256: str,
    *,
    approved_identity_issuers: Mapping[str, Mapping[str, Any]],
) -> None:
    assignment = require_root(graph, root_sha256, frozenset({"PRINCIPAL_ASSIGNMENT"}), label="principal assignment root")
    identity_bindings = [graph.nodes[child] for child in assignment["child_node_ids"] if graph.nodes[child]["node_type"] == "IDENTITY_BINDING"]
    if not identity_bindings:
        raise _fail("PRINCIPAL_IDENTITY_EVIDENCE_INSUFFICIENT", "principal assignment lacks identity binding")
    for binding in identity_bindings:
        records = [graph.nodes[child] for child in binding["child_node_ids"] if graph.nodes[child]["node_type"] == "REGISTRY_RECORD"]
        evidence = [graph.nodes[child] for child in binding["child_node_ids"] if graph.nodes[child]["node_type"] == "UNDERLYING_IDENTITY_EVIDENCE"]
        if not records or not evidence:
            raise _fail("PRINCIPAL_IDENTITY_EVIDENCE_INSUFFICIENT", "identity binding lacks registry and underlying evidence")
        high = [item for item in evidence if item["metadata"].get("assurance") == "HIGH"]
        issuer_groups = {
            item["metadata"].get("issuer_control_group_id")
            for item in evidence
            if type(item["metadata"].get("issuer_control_group_id")) is str
        }
        if not high and len(issuer_groups) < 2:
            raise _fail("PRINCIPAL_IDENTITY_EVIDENCE_INSUFFICIENT", "identity evidence needs one high-assurance credential or two independent issuers")
        for item in evidence:
            receipts = [graph.nodes[child] for child in item["child_node_ids"] if graph.nodes[child]["node_type"] == "ISSUER_AUTHORITY_RECEIPT"]
            if not receipts:
                raise _fail("PRINCIPAL_IDENTITY_EVIDENCE_INSUFFICIENT", "underlying identity evidence lacks issuer receipt")
            for receipt in receipts:
                metadata = receipt["metadata"]
                required = {
                    "issuer_key_id",
                    "issuer_subject_id",
                    "issuer_control_group_id",
                    "issuer_organization_id",
                }
                if set(metadata) != required:
                    raise _fail("PRINCIPAL_IDENTITY_EVIDENCE_INSUFFICIENT", "issuer receipt metadata is incomplete")
                issuer = approved_identity_issuers.get(metadata["issuer_key_id"])
                if issuer is None or any(
                    metadata[field] != issuer[authority_field]
                    for field, authority_field in (
                        ("issuer_subject_id", "subject_id"),
                        ("issuer_control_group_id", "control_group_id"),
                        ("issuer_organization_id", "organization_id"),
                    )
                ):
                    raise _fail("PRINCIPAL_IDENTITY_EVIDENCE_INSUFFICIENT", "identity chain terminates in an unpinned issuer")
                if item["metadata"].get("issuer_control_group_id") != issuer["control_group_id"]:
                    raise _fail("PRINCIPAL_IDENTITY_EVIDENCE_INSUFFICIENT", "identity evidence and issuer receipt control groups disagree")


def component_assignment_id(
    *,
    component_kind: str,
    member_slot_ids: Sequence[str],
    pair_classification_graph_root_sha256: str,
) -> str:
    if component_kind not in _COMPONENT_PREFIX:
        raise _fail("COMPONENT_ID_RECOMPUTATION_MISMATCH", "unknown component kind")
    members = list(member_slot_ids)
    if not members or members != sorted(members) or len(set(members)) != len(members):
        raise _fail("COMPONENT_ID_RECOMPUTATION_MISMATCH", "component members must be sorted and unique")
    for member in members:
        _identifier(member, "component member slot id", code="COMPONENT_ID_RECOMPUTATION_MISMATCH")
    pair_root = _sha(
        pair_classification_graph_root_sha256,
        "pair classification graph root",
        code="COMPONENT_ID_RECOMPUTATION_MISMATCH",
    )
    digest = hashlib.sha256(
        b"EVAL-V626/COMPONENT-ID\0"
        + canonical_json_bytes(
            {
                "component_kind": component_kind,
                "member_slot_ids": members,
                "pair_classification_graph_root_sha256": pair_root,
            }
        )
    ).hexdigest()
    return f"{_COMPONENT_PREFIX[component_kind]}-{digest[:24]}"


def _descendants(graph: EvidenceGraph, root: str) -> set[str]:
    pending = [root]
    result: set[str] = set()
    while pending:
        current = pending.pop()
        for child in graph.nodes[current]["child_node_ids"]:
            if child not in result:
                result.add(child)
                pending.append(child)
    return result


def validate_population_derivation(
    graph: EvidenceGraph,
    *,
    evidence_input_graph_root_sha256: str,
    pair_classification_graph_root_sha256: str,
    component_assignment_root_sha256: str,
    population_decision_root_sha256: str,
) -> dict[str, tuple[str, ...]]:
    evidence_input = require_root(
        graph,
        evidence_input_graph_root_sha256,
        frozenset({"EVIDENCE_INPUT_GRAPH_ROOT"}),
        label="evidence input graph root",
    )
    pair_root = require_root(
        graph,
        pair_classification_graph_root_sha256,
        frozenset({"PAIR_CLASSIFICATION_GRAPH_ROOT"}),
        label="pair classification graph root",
    )
    assignment_root = require_root(
        graph,
        component_assignment_root_sha256,
        frozenset({"COMPONENT_ASSIGNMENT_ROOT"}),
        label="component assignment root",
    )
    decision_root = require_root(
        graph,
        population_decision_root_sha256,
        frozenset({"POPULATION_DECISION_ROOT"}),
        label="population decision root",
    )
    forbidden_early_types = {
        "COMPONENT_ASSIGNMENT",
        "COMPONENT_ASSIGNMENT_ROOT",
        "POPULATION_DECISION_ROOT",
    }
    for stage_root in (evidence_input, pair_root):
        stage_nodes = {stage_root["node_id"], *_descendants(graph, stage_root["node_id"])}
        if any(graph.nodes[node_id]["node_type"] in forbidden_early_types for node_id in stage_nodes):
            raise _fail("COMPONENT_DERIVATION_CIRCULAR", "an upstream derivation stage contains a component assignment or population decision")
        if any("component_id" in graph.nodes[node_id]["metadata"] for node_id in stage_nodes):
            raise _fail("COMPONENT_DERIVATION_CIRCULAR", "an upstream derivation stage contains a derived component id")
    if any(graph.nodes[child]["node_type"] != "PAIR_ANALYSIS_ROOT" for child in pair_root["child_node_ids"]):
        raise _fail("DERIVATION_STAGE_VIOLATION", "pair classification root may contain only pair analysis roots")
    if set(assignment_root["child_node_ids"]) == set() or any(
        graph.nodes[child]["node_type"] != "COMPONENT_ASSIGNMENT"
        for child in assignment_root["child_node_ids"]
    ):
        raise _fail("DERIVATION_STAGE_VIOLATION", "component assignment root may contain only component assignments")
    if assignment_root["metadata"].get("pair_classification_graph_root_sha256") != pair_root["node_id"]:
        raise _fail("DERIVATION_STAGE_VIOLATION", "component assignment root does not bind the pair classification stage")
    by_kind: dict[str, list[str]] = defaultdict(list)
    for child in assignment_root["child_node_ids"]:
        node = graph.nodes[child]
        metadata = node["metadata"]
        if set(metadata) != {
            "component_kind",
            "component_id",
            "member_slot_ids",
            "pair_classification_graph_root_sha256",
        }:
            raise _fail("DERIVATION_STAGE_VIOLATION", "component assignment metadata is incomplete")
        component_id = metadata["component_id"]
        if type(component_id) is not str or _COMPONENT_ID_RE.fullmatch(component_id) is None:
            raise _fail("COMPONENT_ID_RECOMPUTATION_MISMATCH", "component id encoding is invalid")
        expected = component_assignment_id(
            component_kind=metadata["component_kind"],
            member_slot_ids=metadata["member_slot_ids"],
            pair_classification_graph_root_sha256=metadata["pair_classification_graph_root_sha256"],
        )
        if metadata["pair_classification_graph_root_sha256"] != pair_root["node_id"] or component_id != expected:
            raise _fail("COMPONENT_ID_RECOMPUTATION_MISMATCH", "component id is not derived from membership and the pair classification root")
        by_kind[metadata["component_kind"]].append(component_id)
    if set(by_kind) != set(_COMPONENT_PREFIX):
        raise _fail("DERIVATION_STAGE_VIOLATION", "all three component kinds are required")
    required_decision_children = {
        evidence_input["node_id"],
        pair_root["node_id"],
        assignment_root["node_id"],
    }
    if set(decision_root["child_node_ids"]) != required_decision_children:
        raise _fail("DERIVATION_STAGE_VIOLATION", "population decision must bind exactly the three upstream stages")
    expected_metadata = {
        "evidence_input_graph_root_sha256": evidence_input["node_id"],
        "pair_classification_graph_root_sha256": pair_root["node_id"],
        "component_assignment_root_sha256": assignment_root["node_id"],
    }
    if decision_root["metadata"] != expected_metadata:
        raise _fail("DERIVATION_STAGE_VIOLATION", "population decision stage metadata does not bind the exact upstream roots")
    return {kind: tuple(sorted(values)) for kind, values in by_kind.items()}


_RUNTIME_FIELDS = frozenset(
    {
        "schema",
        "verifier_source_commit_sha256",
        "verifier_source_tree_sha256",
        "entrypoint_module_sha256",
        "transitive_python_manifest_root_sha256",
        "interpreter_executable_sha256",
        "interpreter_version",
        "native_library_manifest_root_sha256",
        "dependency_lock_sha256",
        "cryptographic_library_manifest_root_sha256",
        "evidence_loader_sha256",
        "canonicalization_implementation_sha256",
        "container_image_digest",
        "kernel_declaration",
        "architecture",
        "policy_config_root_sha256",
        "command_line_sha256",
        "working_directory_identity",
        "environment_allowlist_root_sha256",
        "network_endpoint_policy_root_sha256",
        "runtime_custodian_subject_id",
        "runtime_custodian_control_group_id",
        "runtime_custodian_organization_id",
        "accepted_verifier_build_root_sha256",
        "runtime_tcb_policy_sha256",
    }
)


def _payload_json(graph: EvidenceGraph, node: Mapping[str, Any], *, code: str, label: str) -> Mapping[str, Any]:
    digest = node["payload_sha256"]
    if digest is None or digest not in graph.payloads:
        raise _fail(code, f"{label} has no closed payload")
    try:
        value = canonical_json_loads(graph.payloads[digest])
    except Exception as exc:
        raise _fail(code, f"{label} payload is not canonical JSON") from exc
    if type(value) is not dict or canonical_json_bytes(value) != graph.payloads[digest]:
        raise _fail(code, f"{label} payload is not a canonical JSON object")
    return value


def validate_runtime_manifest(
    graph: EvidenceGraph,
    root_sha256: str,
    *,
    accepted_verifier_build_root_sha256: str,
    runtime_tcb_policy_sha256: str,
) -> RuntimeManifest:
    code = "VERIFIER_TCB_MANIFEST_INCOMPLETE"
    node = require_root(graph, root_sha256, frozenset({"RUNTIME_MANIFEST"}), label="runtime manifest root")
    payload = _exact(_payload_json(graph, node, code=code, label="runtime manifest"), _RUNTIME_FIELDS, "runtime manifest", code=code)
    if payload["schema"] != RUNTIME_MANIFEST_SCHEMA:
        raise _fail(code, "runtime manifest schema mismatch")
    for field in (
        "verifier_source_commit_sha256",
        "verifier_source_tree_sha256",
        "entrypoint_module_sha256",
        "interpreter_executable_sha256",
        "dependency_lock_sha256",
        "evidence_loader_sha256",
        "canonicalization_implementation_sha256",
        "command_line_sha256",
        "accepted_verifier_build_root_sha256",
        "runtime_tcb_policy_sha256",
    ):
        _sha(payload[field], f"runtime manifest {field}", code=code)
    for field in (
        "interpreter_version",
        "kernel_declaration",
        "architecture",
        "working_directory_identity",
        "runtime_custodian_subject_id",
        "runtime_custodian_control_group_id",
        "runtime_custodian_organization_id",
    ):
        _identifier(payload[field], f"runtime manifest {field}", code=code)
    if type(payload["container_image_digest"]) is not str or _CONTAINER_DIGEST_RE.fullmatch(payload["container_image_digest"]) is None:
        raise _fail(code, "runtime manifest container image digest is invalid")
    root_fields = {
        "transitive_python_manifest_root_sha256": "PYTHON_MODULE_MANIFEST",
        "native_library_manifest_root_sha256": "NATIVE_LIBRARY_MANIFEST",
        "cryptographic_library_manifest_root_sha256": "CRYPTO_LIBRARY_MANIFEST",
        "policy_config_root_sha256": "POLICY_CONFIG_MANIFEST",
        "environment_allowlist_root_sha256": "ENVIRONMENT_ALLOWLIST",
        "network_endpoint_policy_root_sha256": "NETWORK_ENDPOINT_POLICY",
    }
    child_ids = set(node["child_node_ids"])
    for field, node_type in root_fields.items():
        child_root = _sha(payload[field], f"runtime manifest {field}", code=code)
        child_node = require_root(graph, child_root, frozenset({node_type}), label=field)
        if child_node["payload_sha256"] is None:
            raise _fail(code, f"runtime TCB child {field} lacks a closed manifest payload")
        _payload_json(graph, child_node, code=code, label=field)
        if child_root not in child_ids:
            raise _fail(code, f"runtime manifest does not bind {field} as a child")
    if payload["accepted_verifier_build_root_sha256"] != accepted_verifier_build_root_sha256 or payload["runtime_tcb_policy_sha256"] != runtime_tcb_policy_sha256:
        raise _fail("VERIFIER_TCB_MISMATCH", "runtime manifest build or TCB policy differs from the release pin")
    return RuntimeManifest(
        node_id=node["node_id"],
        runtime_custodian_subject_id=payload["runtime_custodian_subject_id"],
        runtime_custodian_control_group_id=payload["runtime_custodian_control_group_id"],
        runtime_custodian_organization_id=payload["runtime_custodian_organization_id"],
        accepted_verifier_build_root_sha256=payload["accepted_verifier_build_root_sha256"],
        runtime_tcb_policy_sha256=payload["runtime_tcb_policy_sha256"],
    )


_TRANSCRIPT_FIELDS = frozenset(
    {
        "schema",
        "session_id",
        "authority_challenge",
        "verification_nonce",
        "runtime_manifest_root_sha256",
        "events",
    }
)


def validate_execution_transcript(graph: EvidenceGraph, root_sha256: str, *, runtime_manifest_root_sha256: str) -> ExecutionTranscript:
    code = "VERIFIER_TCB_MANIFEST_INCOMPLETE"
    node = require_root(graph, root_sha256, frozenset({"EXECUTION_TRANSCRIPT"}), label="execution transcript root")
    payload = _exact(_payload_json(graph, node, code=code, label="execution transcript"), _TRANSCRIPT_FIELDS, "execution transcript", code=code)
    if payload["schema"] != EXECUTION_TRANSCRIPT_SCHEMA or payload["runtime_manifest_root_sha256"] != runtime_manifest_root_sha256:
        raise _fail("VERIFIER_TCB_MISMATCH", "execution transcript schema or runtime binding mismatch")
    events = payload["events"]
    if type(events) is not list or not events:
        raise _fail(code, "execution transcript requires an event stream")
    parsed_types: list[str] = []
    for index, raw in enumerate(events):
        event = _exact(raw, frozenset({"sequence", "event_type", "artifact_root_sha256", "detail_sha256"}), f"transcript event[{index}]", code=code)
        if _decimal(event["sequence"], "transcript event sequence", code=code) != index:
            raise _fail(code, "transcript event sequence is not contiguous from zero")
        parsed_types.append(_identifier(event["event_type"], "transcript event type", code=code))
        if event["artifact_root_sha256"] is not None:
            root = _sha(event["artifact_root_sha256"], "transcript event artifact root", code=code)
            if root not in graph.nodes:
                raise _fail("EVIDENCE_GRAPH_DANGLING", "transcript event references an absent artifact root")
        _sha(event["detail_sha256"], "transcript event detail", code=code)
    cursor = 0
    for event_type in parsed_types:
        if cursor < len(REQUIRED_TRANSCRIPT_EVENTS) and event_type == REQUIRED_TRANSCRIPT_EVENTS[cursor]:
            cursor += 1
    if cursor != len(REQUIRED_TRANSCRIPT_EVENTS):
        raise _fail(code, "execution transcript omits or reorders mandatory events")
    return ExecutionTranscript(
        node_id=node["node_id"],
        session_id=_identifier(payload["session_id"], "transcript session id", code=code),
        authority_challenge=_nonce(payload["authority_challenge"], "transcript authority challenge", code=code),
        verification_nonce=_nonce(payload["verification_nonce"], "transcript verification nonce", code=code),
        runtime_manifest_root_sha256=payload["runtime_manifest_root_sha256"],
        event_types=tuple(parsed_types),
    )


__all__ = [
    "DOMAIN_EVIDENCE_GRAPH",
    "DOMAIN_EVIDENCE_NODE",
    "EDGE_RELATIONS",
    "EVIDENCE_EDGE_SCHEMA",
    "EVIDENCE_FAILURE_STATES",
    "EVIDENCE_NODE_SCHEMA",
    "EVIDENCE_PAYLOAD_SCHEMA",
    "EXECUTION_TRANSCRIPT_SCHEMA",
    "EvidenceGraph",
    "EvidenceV626Error",
    "ExecutionTranscript",
    "NODE_TYPES",
    "RUNTIME_MANIFEST_SCHEMA",
    "RuntimeManifest",
    "evidence_graph_root",
    "evidence_node_id",
    "component_assignment_id",
    "require_root",
    "validate_evidence_graph",
    "validate_execution_transcript",
    "validate_pair_analysis",
    "validate_population_derivation",
    "validate_principal_assignment",
    "validate_runtime_manifest",
]
