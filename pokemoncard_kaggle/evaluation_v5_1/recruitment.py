"""Fail-closed v5.1 recruitment, ancestry, and roster replay evidence.

This module verifies evidence; it is not a registry authority.  In particular,
``closed=True`` means only that this local append log was closed.  Exhaustive
public intake coverage remains an external observer/registry fact and is
reported as unverified here unless such evidence is separately supplied.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import re
from typing import Any

from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.envelope import EnvelopeError, verify_envelope


PLAN_SCHEMA = "evaluation_v5_1_recruitment_plan_v1"
ANCESTRY_SCHEMA = "evaluation_v5_1_transitive_ancestry_dag_v1"
INTAKE_ENTRY_SCHEMA = "evaluation_v5_1_intake_entry_v1"
INTAKE_LEDGER_SCHEMA = "evaluation_v5_1_append_only_intake_ledger_v1"
FAMILY_REPORT_SCHEMA = "evaluation_v5_1_derived_family_report_v1"
LOTTERY_SCHEMA = "evaluation_v5_1_future_beacon_roster_replay_v1"
PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"

RECRUITMENT_PLAN_SCHEMA = PLAN_SCHEMA
TRANSITIVE_ANCESTRY_SCHEMA = ANCESTRY_SCHEMA
GLOBAL_ANCESTRY_DAG_SCHEMA = ANCESTRY_SCHEMA

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_ZERO_HASH = "0" * 64
_NODE_TYPES = frozenset({"ARCHIVE", "POLICY", "TEACHER", "CHECKPOINT", "SOURCE_TREE", "DERIVATION_EVIDENCE"})
_TERMINAL_TYPES = frozenset({"CHECKPOINT", "SOURCE_TREE", "DERIVATION_EVIDENCE"})
_EDGE_TYPES = frozenset({"PARENT", "TEACHER", "CHECKPOINT", "SOURCE_TREE", "DERIVATION"})
_EDGE_FIELDS = frozenset({"edge_type", "source", "target"})
_INCOMPLETE_POLICIES = frozenset({"EXCLUDE", "UNKNOWN_FAMILY"})
_DECISIONS = frozenset({"ACCEPTED", "REJECTED"})
_EXCLUSION_CODES = frozenset(
    {
        "NONE",
        "DUPLICATE_ARCHIVE",
        "OUTSIDE_INTAKE_WINDOW",
        "INVALID_ANCESTRY_DAG",
        "INCOMPLETE_ANCESTRY",
        "FAMILY_CAP_EXCEEDED",
    }
)

_PLAN_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "target_population",
        "allowed_eligibility_fields",
        "strata",
        "intake_open_utc",
        "intake_close_utc",
        "exclusion_codes",
        "family_cap",
        "future_beacon_round",
        "future_beacon_identity",
        "dev_seed_commitment_sha256",
        "registrar_seed_commitment_sha256",
        "seed_derivation_rule",
        "lottery_algorithm",
        "no_replacement",
        "incomplete_ancestry_policy",
        "outcome_free",
        "authority",
        "content_sha256",
    }
)
_TARGET_FIELDS = frozenset(
    {
        "selected_families",
        "selected_archives",
        "strata",
        "families_per_stratum",
        "archives_per_selected_family",
        "activation_blocks",
        "archives_per_activation_block",
    }
)
_STRATUM_FIELDS = frozenset({"stratum_id", "family_count_target"})
_NODE_FIELDS = frozenset({"node_type", "content_sha256", "complete", "derivation_evidence_sha256s"})
_DAG_FIELDS = frozenset(
    {"schema", "protocol_id", "nodes", "edges", "cohort_archive_roots", "declared_terminal_roots", "content_sha256"}
)
_CANDIDATE_FIELDS = frozenset(
    {"archive_sha256", "deck_sha256", "policy_sha256", "intake_timestamp_utc"}
)
_ENTRY_FIELDS = frozenset(
    {
        "schema",
        "intake_sequence",
        "previous_entry_sha256",
        "archive_sha256",
        "deck_sha256",
        "policy_sha256",
        "intake_timestamp_utc",
        "decision",
        "exclusion_code",
        "content_sha256",
    }
)
_LEDGER_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "ancestry_dag_sha256",
        "entries",
        "closed",
        "closed_after_entry_sha256",
        "external_registry_evidence_sha256",
        "external_registry_authority",
        "externally_exhaustive",
        "content_sha256",
    }
)
_LOTTERY_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "plan_sha256",
        "intake_content_sha256",
        "ancestry_dag_sha256",
        "future_beacon_sha256",
        "future_beacon_round",
        "future_beacon_identity",
        "seed_sha256",
        "lottery_algorithm",
        "no_replacement",
        "accepted_archive_sha256s",
        "selected_family_ids",
        "ordered_family_ids",
        "ordered_strata",
        "family_earliest_registration_utc",
        "selected_family_strata",
        "selected_family_archives",
        "selected_archive_sha256s",
        "activation_blocks",
        "content_sha256",
    }
)

_FORBIDDEN_INPUT_KEYS = frozenset(
    {"outcome", "feature", "features", "team", "team_score", "score", "prediction", "probability", "win", "loss", "family_id", "family_label"}
)


class RecruitmentError(ValueError):
    """Base error for malformed or untrusted recruitment evidence."""


class PlanError(RecruitmentError):
    pass


class AncestryError(RecruitmentError):
    pass


class IntakeError(RecruitmentError):
    pass


class LotteryError(RecruitmentError):
    pass


def _exact(value: object, fields: frozenset[str], *, label: str, error: type[RecruitmentError]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise error(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _reject_forbidden(value: object, *, error: type[RecruitmentError], path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str:
                raise error(f"{path} contains a non-string key")
            if key.lower() in _FORBIDDEN_INPUT_KEYS:
                raise error(f"{path}.{key} is forbidden in outcome-free recruitment evidence")
            _reject_forbidden(child, error=error, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden(child, error=error, path=f"{path}[{index}]")


def _sha256(value: object, *, label: str, error: type[RecruitmentError]) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise error(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _utc(value: object, *, label: str, error: type[RecruitmentError]) -> str:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise error(f"{label} must be canonical UTC with microseconds")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise error(f"{label} is not a valid UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise error(f"{label} must be UTC")
    if parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z") != value:
        raise error(f"{label} is not canonical UTC")
    return value


def _hash_list(value: object, *, label: str, error: type[RecruitmentError]) -> list[str]:
    if type(value) is not list:
        raise error(f"{label} must be a JSON list")
    result = [_sha256(item, label=f"{label}[{index}]", error=error) for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise error(f"{label} must not contain duplicates")
    return sorted(result)


def _node_id(node: Mapping[str, Any]) -> str:
    return f"{node['node_type']}:{node['content_sha256']}"


def _node_id_from(node_type: str, content_sha256: str) -> str:
    return f"{node_type}:{content_sha256}"


def _assert_acyclic(edges: Iterable[Mapping[str, str]], *, error: type[RecruitmentError]) -> None:
    outgoing: dict[str, set[str]] = {}
    indegree: dict[str, int] = {}
    for edge in edges:
        source, target = edge["source"], edge["target"]
        targets = outgoing.setdefault(source, set())
        if target in targets:
            continue
        targets.add(target)
        outgoing.setdefault(target, set())
        indegree.setdefault(source, 0)
        indegree[target] = indegree.get(target, 0) + 1
    queue = sorted(node for node, degree in indegree.items() if degree == 0)
    visited = 0
    while queue:
        node = queue.pop(0)
        visited += 1
        for target in sorted(outgoing[node]):
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
                queue.sort()
    if visited != len(indegree):
        raise error("ancestry DAG contains a directed cycle")


def commit_recruitment_seed(seed: str) -> str:
    """Return the preregisterable commitment for a non-empty ASCII seed."""

    if type(seed) is not str or not seed or seed.strip() != seed or "\0" in seed:
        raise PlanError("seed must be a non-empty trimmed string without NUL")
    try:
        encoded = seed.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PlanError("seed must be ASCII") from exc
    return hashlib.sha256(encoded).hexdigest()


def build_recruitment_plan(
    *,
    intake_open_utc: str = "2026-07-15T00:00:00.000000Z",
    intake_close_utc: str = "2026-11-12T00:00:00.000000Z",
    incomplete_ancestry_policy: str = "UNKNOWN_FAMILY",
    dev_seed_commitment_sha256: str,
    registrar_seed_commitment_sha256: str,
) -> dict[str, Any]:
    if incomplete_ancestry_policy not in _INCOMPLETE_POLICIES:
        raise PlanError("incomplete_ancestry_policy must be EXCLUDE or UNKNOWN_FAMILY")
    opened = _utc(intake_open_utc, label="intake_open_utc", error=PlanError)
    closed = _utc(intake_close_utc, label="intake_close_utc", error=PlanError)
    if opened >= closed:
        raise PlanError("intake window must be strictly increasing")
    _sha256(dev_seed_commitment_sha256, label="dev_seed_commitment_sha256", error=PlanError)
    _sha256(registrar_seed_commitment_sha256, label="registrar_seed_commitment_sha256", error=PlanError)
    strata = [
        {"stratum_id": f"stratum-{index}", "family_count_target": 5}
        for index in range(1, 5)
    ]
    core = {
        "schema": PLAN_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "target_population": {
            "selected_families": 20,
            "selected_archives": 20,
            "strata": 4,
            "families_per_stratum": 5,
            "archives_per_selected_family": 1,
            "activation_blocks": 4,
            "archives_per_activation_block": 5,
        },
        "allowed_eligibility_fields": sorted(_CANDIDATE_FIELDS),
        "strata": strata,
        "intake_open_utc": opened,
        "intake_close_utc": closed,
        "exclusion_codes": sorted(_EXCLUSION_CODES),
        "family_cap": 2,
        "future_beacon_round": "MCI_FAMILY_TRANSFER_V2_RECRUITMENT_ROSTER_001",
        "future_beacon_identity": "opaque_external_beacon_sha256",
        "dev_seed_commitment_sha256": dev_seed_commitment_sha256,
        "registrar_seed_commitment_sha256": registrar_seed_commitment_sha256,
        "seed_derivation_rule": "sha256_ascii_dev_seed_colon_registrar_seed_colon_future_beacon_colon_plan_sha256_v2",
        "lottery_algorithm": "sha256_ascii_beacon_plan_archive_rank_v2_no_replacement",
        "no_replacement": True,
        "incomplete_ancestry_policy": incomplete_ancestry_policy,
        "outcome_free": True,
        "authority": False,
    }
    return {**core, "content_sha256": canonical_sha256(core)}


def validate_recruitment_plan(value: object) -> dict[str, Any]:
    raw = _exact(value, _PLAN_FIELDS, label="recruitment plan", error=PlanError)
    _reject_forbidden(raw, error=PlanError)
    if raw["schema"] != PLAN_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        raise PlanError("recruitment plan schema or protocol_id mismatch")
    _utc(raw["intake_open_utc"], label="intake_open_utc", error=PlanError)
    _utc(raw["intake_close_utc"], label="intake_close_utc", error=PlanError)
    if raw["intake_open_utc"] >= raw["intake_close_utc"]:
        raise PlanError("intake window must be strictly increasing")
    target = _exact(raw["target_population"], _TARGET_FIELDS, label="target_population", error=PlanError)
    expected_target = {
        "selected_families": 20,
        "selected_archives": 20,
        "strata": 4,
        "families_per_stratum": 5,
        "archives_per_selected_family": 1,
        "activation_blocks": 4,
        "archives_per_activation_block": 5,
    }
    if dict(target) != expected_target:
        raise PlanError("target_population is not the frozen v5.1 target")
    if raw["allowed_eligibility_fields"] != sorted(_CANDIDATE_FIELDS):
        raise PlanError("allowed_eligibility_fields is not the exact frozen set")
    strata = raw["strata"]
    if type(strata) is not list or len(strata) != 4:
        raise PlanError("strata must contain exactly four ordered strata")
    for index, item in enumerate(strata, start=1):
        stratum = _exact(item, _STRATUM_FIELDS, label="stratum", error=PlanError)
        if stratum["stratum_id"] != f"stratum-{index}":
            raise PlanError("strata must use canonical ids")
        if stratum["family_count_target"] != 5:
            raise PlanError("each stratum must target exactly five families")
    if raw["exclusion_codes"] != sorted(_EXCLUSION_CODES):
        raise PlanError("exclusion_codes are not the exact frozen set")
    constants = {
        "family_cap": 2,
        "future_beacon_round": "MCI_FAMILY_TRANSFER_V2_RECRUITMENT_ROSTER_001",
        "future_beacon_identity": "opaque_external_beacon_sha256",
        "seed_derivation_rule": "sha256_ascii_dev_seed_colon_registrar_seed_colon_future_beacon_colon_plan_sha256_v2",
        "lottery_algorithm": "sha256_ascii_beacon_plan_archive_rank_v2_no_replacement",
        "no_replacement": True,
        "outcome_free": True,
        "authority": False,
    }
    for key, expected in constants.items():
        if raw[key] != expected:
            raise PlanError(f"{key} is not the frozen v5.1 value")
    _sha256(raw["dev_seed_commitment_sha256"], label="dev_seed_commitment_sha256", error=PlanError)
    _sha256(raw["registrar_seed_commitment_sha256"], label="registrar_seed_commitment_sha256", error=PlanError)
    if raw["incomplete_ancestry_policy"] not in _INCOMPLETE_POLICIES:
        raise PlanError("incomplete_ancestry_policy is invalid")
    core = {key: raw[key] for key in _PLAN_FIELDS if key != "content_sha256"}
    if raw["content_sha256"] != canonical_sha256(core):
        raise PlanError("recruitment plan content_sha256 mismatch")
    return {**core, "content_sha256": raw["content_sha256"]}


def validate_recruitment_plan_envelope(value: object, *, pinned_public_key_bytes: bytes) -> dict[str, Any]:
    """Verify the package-local v5.1 envelope, then validate its plan payload."""

    try:
        payload = verify_envelope(
            value,
            expected_artifact_schema=PLAN_SCHEMA,
            pinned_public_key_bytes=pinned_public_key_bytes,
        )
    except EnvelopeError as exc:
        raise PlanError(f"recruitment plan envelope is invalid: {exc}") from exc
    return validate_recruitment_plan(payload)


def derive_commit_reveal_seed(
    plan: object,
    *,
    dev_seed: str,
    registrar_seed: str,
    future_beacon_sha256: str,
) -> str:
    """Verify both frozen commitments and derive the one replay seed."""

    frozen = validate_recruitment_plan(plan)
    if commit_recruitment_seed(dev_seed) != frozen["dev_seed_commitment_sha256"]:
        raise LotteryError("developer seed does not open its frozen commitment")
    if commit_recruitment_seed(registrar_seed) != frozen["registrar_seed_commitment_sha256"]:
        raise LotteryError("registrar seed does not open its frozen commitment")
    beacon = _sha256(future_beacon_sha256, label="future_beacon_sha256", error=LotteryError)
    return hashlib.sha256(
        f"{dev_seed}:{registrar_seed}:{beacon}:{frozen['content_sha256']}".encode("ascii")
    ).hexdigest()


def _validate_node(value: object, *, index: int) -> dict[str, Any]:
    raw = _exact(value, _NODE_FIELDS, label=f"ancestry node {index}", error=AncestryError)
    if raw["node_type"] not in _NODE_TYPES:
        raise AncestryError("ancestry node type is invalid")
    _sha256(raw["content_sha256"], label="node content_sha256", error=AncestryError)
    if type(raw["complete"]) is not bool:
        raise AncestryError("node complete must be exactly boolean")
    evidence = _hash_list(raw["derivation_evidence_sha256s"], label="node derivation evidence", error=AncestryError)
    if not evidence:
        raise AncestryError("every ancestry node requires derivation evidence")
    return {"node_type": raw["node_type"], "content_sha256": raw["content_sha256"], "complete": raw["complete"], "derivation_evidence_sha256s": evidence}


def _validate_dag_shape(value: object) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[dict[str, str]]]:
    raw = _exact(value, _DAG_FIELDS, label="ancestry DAG", error=AncestryError)
    _reject_forbidden(raw, error=AncestryError)
    if raw["schema"] != ANCESTRY_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        raise AncestryError("ancestry DAG schema or protocol_id mismatch")
    if type(raw["nodes"]) is not list or not raw["nodes"]:
        raise AncestryError("ancestry DAG nodes must be a non-empty list")
    nodes: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw["nodes"]):
        node = _validate_node(item, index=index)
        node_id = _node_id(node)
        if node_id in nodes:
            raise AncestryError("ancestry DAG contains duplicate node identity")
        nodes[node_id] = node
    if type(raw["edges"]) is not list:
        raise AncestryError("ancestry DAG edges must be a list")
    edges: list[dict[str, str]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for item in raw["edges"]:
        edge = _exact(item, _EDGE_FIELDS, label="ancestry edge", error=AncestryError)
        if edge["edge_type"] not in _EDGE_TYPES or edge["source"] not in nodes or edge["target"] not in nodes:
            raise AncestryError("ancestry edge type or node reference is invalid")
        key = (edge["edge_type"], edge["source"], edge["target"])
        if key in seen_edges:
            raise AncestryError("ancestry DAG contains duplicate edges")
        seen_edges.add(key)
        source_type, target_type = nodes[edge["source"]]["node_type"], nodes[edge["target"]]["node_type"]
        allowed = {
            "PARENT": source_type == "POLICY" and target_type == "POLICY",
            "TEACHER": source_type == "POLICY" and target_type == "TEACHER",
            "CHECKPOINT": source_type in {"POLICY", "TEACHER"} and target_type == "CHECKPOINT",
            "SOURCE_TREE": source_type == "POLICY" and target_type == "SOURCE_TREE",
            "DERIVATION": source_type in {"ARCHIVE", "POLICY"} and target_type in {"POLICY", "DERIVATION_EVIDENCE"},
        }
        if not allowed[edge["edge_type"]]:
            raise AncestryError("ancestry edge has incompatible typed endpoints")
        edges.append(dict(edge))
    if edges != sorted(edges, key=lambda edge: (edge["source"], edge["edge_type"], edge["target"])):
        raise AncestryError("ancestry edges must be canonically ordered")
    _assert_acyclic(edges, error=AncestryError)
    roots = _hash_list(raw["cohort_archive_roots"], label="cohort_archive_roots", error=AncestryError)
    if not roots:
        raise AncestryError("ancestry DAG must declare cohort archive roots")
    root_ids = [_node_id_from("ARCHIVE", digest) for digest in roots]
    if any(root_id not in nodes for root_id in root_ids):
        raise AncestryError("every cohort archive root must be an ARCHIVE node")
    terminals = raw["declared_terminal_roots"]
    if type(terminals) is not list or terminals != sorted(set(terminals)) or not terminals:
        raise AncestryError("declared_terminal_roots must be sorted and unique")
    for terminal in terminals:
        if terminal not in nodes or nodes[terminal]["node_type"] not in _TERMINAL_TYPES:
            raise AncestryError("declared terminal root must be a checkpoint, source tree, or derivation node")
    expected = {
        "schema": ANCESTRY_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "nodes": sorted(nodes.values(), key=_node_id),
        "edges": edges,
        "cohort_archive_roots": roots,
        "declared_terminal_roots": terminals,
    }
    return expected, nodes, edges


def validate_ancestry_dag(value: object, *, incomplete_ancestry_policy: str = "UNKNOWN_FAMILY") -> dict[str, Any]:
    expected, nodes, edges = _validate_dag_shape(value)
    if incomplete_ancestry_policy not in _INCOMPLETE_POLICIES:
        raise AncestryError("invalid incomplete ancestry policy")
    raw = value
    terminals = set(raw["declared_terminal_roots"])  # type: ignore[index]
    outgoing: dict[str, list[str]] = {node_id: [] for node_id in nodes}
    for edge in edges:
        outgoing[edge["source"]].append(edge["target"])
    reachable: set[str] = set()
    for root_hash in expected["cohort_archive_roots"]:
        start = _node_id_from("ARCHIVE", root_hash)
        stack = [start]
        while stack:
            node_id = stack.pop()
            if node_id in reachable:
                continue
            reachable.add(node_id)
            stack.extend(outgoing[node_id])
    if reachable != set(nodes):
        raise AncestryError("ancestry DAG contains unreachable nodes or omitted reachable ancestry")
    for node_id in reachable:
        if not outgoing[node_id] and node_id not in terminals:
            raise AncestryError("every reachable path must terminate at a declared terminal root")
    if incomplete_ancestry_policy not in _INCOMPLETE_POLICIES:
        raise AncestryError("invalid incomplete ancestry policy")
    for root_hash in expected["cohort_archive_roots"]:
        policy_nodes = [
            edge["target"] for edge in edges
            if edge["source"] == _node_id_from("ARCHIVE", root_hash) and nodes[edge["target"]]["node_type"] == "POLICY"
        ]
        if len(policy_nodes) != 1:
            raise AncestryError("each cohort archive must have exactly one policy derivation edge")
    if raw["content_sha256"] != canonical_sha256(expected):  # type: ignore[index]
        raise AncestryError("ancestry DAG content_sha256 mismatch")
    return {**expected, "content_sha256": raw["content_sha256"]}  # type: ignore[index]


def build_ancestry_dag(
    *,
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, str]],
    cohort_archive_roots: Sequence[str],
    declared_terminal_roots: Sequence[str],
) -> dict[str, Any]:
    core = {
        "schema": ANCESTRY_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "nodes": sorted([dict(node) for node in nodes], key=lambda node: _node_id(node)),
        "edges": [dict(edge) for edge in edges],
        "cohort_archive_roots": sorted(cohort_archive_roots),
        "declared_terminal_roots": sorted(declared_terminal_roots),
    }
    # Validation performs the full graph normalization and closure audit.
    provisional = {**core, "content_sha256": canonical_sha256(core)}
    return validate_ancestry_dag(provisional)


def _archive_policy(dag: Mapping[str, Any], archive_sha256: str) -> str:
    archive_id = _node_id_from("ARCHIVE", archive_sha256)
    policy_targets = [edge["target"] for edge in dag["edges"] if edge["source"] == archive_id and edge["edge_type"] == "DERIVATION"]
    policies = [target for target in policy_targets if target.startswith("POLICY:")]
    if len(policies) != 1:
        raise AncestryError("cohort archive must have one direct policy node")
    return policies[0].split(":", 1)[1]


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, item: str) -> None:
        self.parent.setdefault(item, item)

    def find(self, item: str) -> str:
        self.add(item)
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            prior = self.parent[item]
            self.parent[item] = root
            item = prior
        return root

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[max(left_root, right_root)] = min(left_root, right_root)


def derive_ancestry_families(
    entries: Sequence[Mapping[str, Any]],
    ancestry_dag: object,
    *,
    incomplete_ancestry_policy: str = "UNKNOWN_FAMILY",
) -> dict[str, Any]:
    dag = validate_ancestry_dag(ancestry_dag, incomplete_ancestry_policy=incomplete_ancestry_policy)
    accepted: list[Mapping[str, Any]] = []
    for index, entry in enumerate(entries):
        if set(entry) == _ENTRY_FIELDS:
            normalized_entry = _validate_entry(entry, index=index)
        elif set(entry) == {"decision", "archive_sha256"}:
            normalized_entry = dict(entry)
            if normalized_entry["decision"] not in _DECISIONS:
                raise AncestryError("family input decision is invalid")
            _sha256(normalized_entry["archive_sha256"], label="family input archive", error=AncestryError)
        else:
            raise AncestryError("family input fields must not contain caller labels or extra fields")
        if normalized_entry["decision"] == "ACCEPTED":
            accepted.append(normalized_entry)
    accepted_archives = [_sha256(entry["archive_sha256"], label="accepted archive", error=AncestryError) for entry in accepted]
    if len(accepted_archives) != len(set(accepted_archives)):
        raise AncestryError("accepted archive roots must be unique")
    root_set = set(dag["cohort_archive_roots"])
    if not set(accepted_archives) <= root_set:
        raise AncestryError("accepted archive is absent from the global ancestry DAG")
    union = _UnionFind()
    for node_id in [_node_id(node) for node in dag["nodes"]]:
        union.add(node_id)
    for edge in dag["edges"]:
        union.union(edge["source"], edge["target"])
    incomplete_nodes = {node_id for node_id, node in ((_node_id(node), node) for node in dag["nodes"]) if not node["complete"]}
    if incomplete_nodes and incomplete_ancestry_policy == "EXCLUDE":
        raise AncestryError("incomplete ancestry is excluded by the frozen plan")
    unknown_anchor = "UNKNOWN_FAMILY:incomplete-ancestry"
    if incomplete_nodes and incomplete_ancestry_policy == "UNKNOWN_FAMILY":
        union.add(unknown_anchor)
        for node_id in incomplete_nodes:
            union.union(unknown_anchor, node_id)
    archive_to_family: dict[str, str] = {}
    components: dict[str, list[str]] = {}
    for archive in sorted(accepted_archives):
        root = union.find(_node_id_from("ARCHIVE", archive))
        components.setdefault(root, []).append(archive)
    family_descriptors: dict[str, dict[str, Any]] = {}
    node_map = {_node_id(node): node for node in dag["nodes"]}
    for root, archives in sorted(components.items()):
        component_nodes = sorted(node_id for node_id in union.parent if union.find(node_id) == root)
        unknown = any(node_id in incomplete_nodes for node_id in component_nodes)
        descriptor: dict[str, Any]
        if unknown:
            descriptor = {"schema": FAMILY_REPORT_SCHEMA, "kind": "UNKNOWN_INCOMPLETE_ANCESTRY"}
        else:
            descriptor = {
                "schema": FAMILY_REPORT_SCHEMA,
                "kind": "DECLARED_TRANSITIVE_COMPONENT",
                "archive_sha256s": archives,
                "nodes": component_nodes,
                "edges": sorted(
                    (edge for edge in dag["edges"] if edge["source"] in component_nodes and edge["target"] in component_nodes),
                    key=lambda edge: (edge["source"], edge["edge_type"], edge["target"]),
                ),
            }
        family_id = canonical_sha256(descriptor)
        family_descriptors[family_id] = descriptor
        for archive in archives:
            archive_to_family[archive] = family_id
    counts = {
        "accepted_archive_count": len(accepted_archives),
        "family_count": len(family_descriptors),
        "incomplete_archive_count": sum(1 for archive in accepted_archives if not node_map[_node_id_from("ARCHIVE", archive)]["complete"]),
        "max_archives_in_family": max((len(archives) for archives in components.values()), default=0),
    }
    core = {"schema": FAMILY_REPORT_SCHEMA, "archive_to_family": dict(sorted(archive_to_family.items())), "family_descriptors": dict(sorted(family_descriptors.items())), "counts": counts}
    return {**core, "content_sha256": canonical_sha256(core)}


def _validate_candidate(value: object) -> Mapping[str, Any]:
    raw = _exact(value, _CANDIDATE_FIELDS, label="intake candidate", error=IntakeError)
    _reject_forbidden(raw, error=IntakeError)
    for key in ("archive_sha256", "deck_sha256", "policy_sha256"):
        _sha256(raw[key], label=key, error=IntakeError)
    _utc(raw["intake_timestamp_utc"], label="intake_timestamp_utc", error=IntakeError)
    return raw


def _entry_core(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {key: entry[key] for key in _ENTRY_FIELDS if key != "content_sha256"}


def _ledger_core(ledger: Mapping[str, Any]) -> dict[str, Any]:
    return {key: ledger[key] for key in _LEDGER_FIELDS if key != "content_sha256"}


def _build_entry(sequence: int, previous_hash: str, candidate: Mapping[str, Any], decision: str, code: str) -> dict[str, Any]:
    core = {
        "schema": INTAKE_ENTRY_SCHEMA,
        "intake_sequence": sequence,
        "previous_entry_sha256": previous_hash,
        "archive_sha256": candidate["archive_sha256"],
        "deck_sha256": candidate["deck_sha256"],
        "policy_sha256": candidate["policy_sha256"],
        "intake_timestamp_utc": candidate["intake_timestamp_utc"],
        "decision": decision,
        "exclusion_code": code,
    }
    return {**core, "content_sha256": canonical_sha256(core)}


def _empty_ledger(plan: Mapping[str, Any], dag: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        "schema": INTAKE_LEDGER_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "ancestry_dag_sha256": dag["content_sha256"],
        "entries": [],
        "closed": False,
        "closed_after_entry_sha256": _ZERO_HASH,
        "external_registry_evidence_sha256": None,
        "external_registry_authority": False,
        "externally_exhaustive": False,
    }
    return {**core, "content_sha256": canonical_sha256(core)}


def _validate_entry(entry: object, *, index: int) -> dict[str, Any]:
    raw = _exact(entry, _ENTRY_FIELDS, label=f"intake entry {index}", error=IntakeError)
    _reject_forbidden(raw, error=IntakeError)
    if raw["schema"] != INTAKE_ENTRY_SCHEMA or raw["intake_sequence"] != index:
        raise IntakeError("intake chronology has a missing, reordered, or replaced entry")
    for key in ("previous_entry_sha256", "archive_sha256", "deck_sha256", "policy_sha256"):
        _sha256(raw[key], label=key, error=IntakeError)
    _utc(raw["intake_timestamp_utc"], label="intake_timestamp_utc", error=IntakeError)
    if raw["decision"] not in _DECISIONS or raw["exclusion_code"] not in _EXCLUSION_CODES:
        raise IntakeError("intake decision or exclusion code is invalid")
    if (raw["decision"] == "ACCEPTED") != (raw["exclusion_code"] == "NONE"):
        raise IntakeError("accepted entries require NONE and rejected entries require an exclusion code")
    if raw["content_sha256"] != canonical_sha256(_entry_core(raw)):
        raise IntakeError("intake entry content_sha256 mismatch")
    return dict(raw)


def _expected_code(plan: Mapping[str, Any], entries: Sequence[Mapping[str, Any]], candidate: Mapping[str, Any], dag: Mapping[str, Any]) -> str:
    previous_archives = {entry["archive_sha256"] for entry in entries}
    if candidate["archive_sha256"] in previous_archives:
        return "DUPLICATE_ARCHIVE"
    timestamp = candidate["intake_timestamp_utc"]
    if not plan["intake_open_utc"] <= timestamp < plan["intake_close_utc"]:
        return "OUTSIDE_INTAKE_WINDOW"
    try:
        policy = _archive_policy(dag, candidate["archive_sha256"])
    except AncestryError:
        return "INVALID_ANCESTRY_DAG"
    if policy != candidate["policy_sha256"]:
        return "INVALID_ANCESTRY_DAG"
    try:
        validate_ancestry_dag(dag, incomplete_ancestry_policy=plan["incomplete_ancestry_policy"])
        if any(not node["complete"] for node in dag["nodes"]):
            if plan["incomplete_ancestry_policy"] == "EXCLUDE":
                return "INCOMPLETE_ANCESTRY"
        provisional = [*entries, {"decision": "ACCEPTED", "archive_sha256": candidate["archive_sha256"]}]
        report = derive_ancestry_families(provisional, dag, incomplete_ancestry_policy=plan["incomplete_ancestry_policy"])
        if report["counts"]["max_archives_in_family"] > plan["family_cap"]:
            return "FAMILY_CAP_EXCEEDED"
    except AncestryError:
        return "INVALID_ANCESTRY_DAG"
    return "NONE"


def validate_intake_ledger(plan: object, ledger: object, ancestry_dag: object) -> dict[str, Any]:
    frozen_plan = validate_recruitment_plan(plan)
    dag = validate_ancestry_dag(ancestry_dag, incomplete_ancestry_policy=frozen_plan["incomplete_ancestry_policy"])
    raw = _exact(ledger, _LEDGER_FIELDS, label="intake ledger", error=IntakeError)
    _reject_forbidden(raw, error=IntakeError)
    if raw["schema"] != INTAKE_LEDGER_SCHEMA or raw["protocol_id"] != PROTOCOL_ID or raw["ancestry_dag_sha256"] != dag["content_sha256"]:
        raise IntakeError("intake ledger schema, protocol, or ancestry hash mismatch")
    if type(raw["entries"]) is not list or type(raw["closed"]) is not bool or type(raw["external_registry_authority"]) is not bool or type(raw["externally_exhaustive"]) is not bool:
        raise IntakeError("intake ledger types are invalid")
    if raw["external_registry_authority"] is not False or raw["externally_exhaustive"] is not False:
        raise IntakeError("local intake cannot claim external exhaustiveness authority")
    if raw["external_registry_evidence_sha256"] is not None:
        _sha256(raw["external_registry_evidence_sha256"], label="external_registry_evidence_sha256", error=IntakeError)
    _sha256(raw["closed_after_entry_sha256"], label="closed_after_entry_sha256", error=IntakeError)
    entries: list[dict[str, Any]] = []
    previous_hash = _ZERO_HASH
    previous_timestamp: str | None = None
    for index, item in enumerate(raw["entries"]):
        entry = _validate_entry(item, index=index)
        if entry["previous_entry_sha256"] != previous_hash:
            raise IntakeError("intake entry hash chain is broken; an entry was omitted or replaced")
        if previous_timestamp is not None and entry["intake_timestamp_utc"] <= previous_timestamp:
            raise IntakeError("intake timestamps must be strictly increasing")
        expected = _expected_code(frozen_plan, entries, entry, dag)
        actual = entry["exclusion_code"]
        if actual != expected or entry["decision"] != ("ACCEPTED" if expected == "NONE" else "REJECTED"):
            raise IntakeError("intake decision or exclusion code is not the deterministic frozen result")
        entries.append(entry)
        previous_hash = entry["content_sha256"]
        previous_timestamp = entry["intake_timestamp_utc"]
    last_hash = entries[-1]["content_sha256"] if entries else _ZERO_HASH
    if raw["closed"]:
        if not entries or raw["closed_after_entry_sha256"] != last_hash:
            raise IntakeError("closed intake has no matching closure anchor")
    elif raw["closed_after_entry_sha256"] != _ZERO_HASH:
        raise IntakeError("open intake cannot carry a closure anchor")
    core = {key: raw[key] for key in _LEDGER_FIELDS if key != "content_sha256"}
    core["entries"] = entries
    if raw["content_sha256"] != canonical_sha256(core):
        raise IntakeError("intake ledger content_sha256 mismatch")
    return {**core, "content_sha256": raw["content_sha256"]}


def classify_intake_candidate(plan: object, ledger: object, candidate: object, ancestry_dag: object) -> dict[str, Any]:
    frozen_plan = validate_recruitment_plan(plan)
    dag = validate_ancestry_dag(ancestry_dag, incomplete_ancestry_policy=frozen_plan["incomplete_ancestry_policy"])
    current = validate_intake_ledger(frozen_plan, ledger, dag)
    if current["closed"]:
        raise IntakeError("closed intake cannot receive a post-intake replacement")
    raw = _validate_candidate(candidate)
    if current["entries"] and raw["intake_timestamp_utc"] <= current["entries"][-1]["intake_timestamp_utc"]:
        raise IntakeError("intake candidate timestamp would break chronology")
    code = _expected_code(frozen_plan, current["entries"], raw, dag)
    return _build_entry(len(current["entries"]), current["entries"][-1]["content_sha256"] if current["entries"] else _ZERO_HASH, raw, "ACCEPTED" if code == "NONE" else "REJECTED", code)


def append_intake_entry(plan: object, ledger: object, candidate: object, ancestry_dag: object) -> dict[str, Any]:
    frozen_plan = validate_recruitment_plan(plan)
    dag = validate_ancestry_dag(ancestry_dag, incomplete_ancestry_policy=frozen_plan["incomplete_ancestry_policy"])
    current = validate_intake_ledger(frozen_plan, ledger, dag)
    entry = classify_intake_candidate(frozen_plan, current, candidate, dag)
    core = {**_ledger_core(current), "entries": [*current["entries"], entry], "closed": False, "closed_after_entry_sha256": _ZERO_HASH}
    return validate_intake_ledger(frozen_plan, {**core, "content_sha256": canonical_sha256(core)}, dag)


def build_intake_ledger(plan: object, candidates: Iterable[object], ancestry_dag: object) -> dict[str, Any]:
    frozen_plan = validate_recruitment_plan(plan)
    dag = validate_ancestry_dag(ancestry_dag, incomplete_ancestry_policy=frozen_plan["incomplete_ancestry_policy"])
    ledger = _empty_ledger(frozen_plan, dag)
    for candidate in candidates:
        ledger = append_intake_entry(frozen_plan, ledger, candidate, dag)
    return ledger


def close_intake(plan: object, ledger: object, ancestry_dag: object) -> dict[str, Any]:
    frozen_plan = validate_recruitment_plan(plan)
    dag = validate_ancestry_dag(ancestry_dag, incomplete_ancestry_policy=frozen_plan["incomplete_ancestry_policy"])
    current = validate_intake_ledger(frozen_plan, ledger, dag)
    if current["closed"]:
        return current
    if not current["entries"]:
        raise IntakeError("cannot close an empty intake")
    core = {**_ledger_core(current), "closed": True, "closed_after_entry_sha256": current["entries"][-1]["content_sha256"]}
    return validate_intake_ledger(frozen_plan, {**core, "content_sha256": canonical_sha256(core)}, dag)


def _family_strata(
    plan: Mapping[str, Any], ledger: Mapping[str, Any], report: Mapping[str, Any]
) -> dict[str, Any]:
    earliest: dict[str, str] = {}
    for entry in ledger["entries"]:
        if entry["decision"] != "ACCEPTED":
            continue
        family = report["archive_to_family"][entry["archive_sha256"]]
        timestamp = entry["intake_timestamp_utc"]
        if family not in earliest or timestamp < earliest[family]:
            earliest[family] = timestamp
    ordered_family_ids = sorted(earliest, key=lambda family: (earliest[family], family))
    if len(ordered_family_ids) < plan["target_population"]["selected_families"]:
        raise IntakeError("fewer than 20 effective families are available after ancestry merging")
    base, remainder = divmod(len(ordered_family_ids), plan["target_population"]["strata"])
    sizes = [base + (1 if index < remainder else 0) for index in range(plan["target_population"]["strata"])]
    if any(size < plan["target_population"]["families_per_stratum"] for size in sizes):
        raise IntakeError("fewer than five effective families are available in a frozen stratum")
    ordered_strata: list[dict[str, Any]] = []
    family_strata: dict[str, str] = {}
    offset = 0
    for index, size in enumerate(sizes, start=1):
        family_ids = ordered_family_ids[offset : offset + size]
        stratum_id = f"stratum-{index}"
        ordered_strata.append({"stratum_id": stratum_id, "family_ids": family_ids})
        for family in family_ids:
            family_strata[family] = stratum_id
        offset += size
    return {
        "ordered_family_ids": ordered_family_ids,
        "ordered_strata": ordered_strata,
        "family_strata": family_strata,
        "family_earliest_registration_utc": {family: earliest[family] for family in ordered_family_ids},
    }


def validate_recruitment_population(plan: object, ledger: object, ancestry_dag: object) -> dict[str, Any]:
    frozen_plan = validate_recruitment_plan(plan)
    frozen_ledger = validate_intake_ledger(frozen_plan, ledger, ancestry_dag)
    if not frozen_ledger["closed"]:
        raise IntakeError("recruitment population must be closed before the future beacon")
    report = derive_ancestry_families(frozen_ledger["entries"], ancestry_dag, incomplete_ancestry_policy=frozen_plan["incomplete_ancestry_policy"])
    target = frozen_plan["target_population"]
    if report["counts"]["family_count"] < target["selected_families"]:
        raise IntakeError("later transitive ancestry merges leave fewer than 20 effective families")
    if report["counts"]["max_archives_in_family"] > frozen_plan["family_cap"]:
        raise IntakeError("recruitment population exceeds the frozen family cap")
    family_partition = _family_strata(frozen_plan, frozen_ledger, report)
    stratum_counts = {stratum["stratum_id"]: len(stratum["family_ids"]) for stratum in family_partition["ordered_strata"]}
    return {
        "plan": frozen_plan,
        "ledger": frozen_ledger,
        "ancestry_dag": validate_ancestry_dag(ancestry_dag, incomplete_ancestry_policy=frozen_plan["incomplete_ancestry_policy"]),
        "family_report": report,
        "family_strata": family_partition["family_strata"],
        "ordered_family_ids": family_partition["ordered_family_ids"],
        "ordered_strata": family_partition["ordered_strata"],
        "family_earliest_registration_utc": family_partition["family_earliest_registration_utc"],
        "stratum_counts": stratum_counts,
        "authority": False,
        "externally_exhaustive": False,
        "prior_exact_archive_hosted_outcomes_verified": False,
    }


def _lottery_rank(seed: str, domain: str, value: str) -> str:
    return hashlib.sha256(f"{seed}:{domain}:{value}".encode("ascii")).hexdigest()


def replay_roster_lottery(
    plan: object,
    ledger: object,
    ancestry_dag: object,
    future_beacon_sha256: str,
    *,
    dev_seed: str,
    registrar_seed: str,
    future_beacon_round: str | None = None,
    future_beacon_identity: str | None = None,
) -> dict[str, Any]:
    population = validate_recruitment_population(plan, ledger, ancestry_dag)
    frozen_plan, frozen_ledger, dag = population["plan"], population["ledger"], population["ancestry_dag"]
    beacon = _sha256(future_beacon_sha256, label="future_beacon_sha256", error=LotteryError)
    round_id = future_beacon_round if future_beacon_round is not None else frozen_plan["future_beacon_round"]
    identity = future_beacon_identity if future_beacon_identity is not None else frozen_plan["future_beacon_identity"]
    if round_id != frozen_plan["future_beacon_round"] or identity != frozen_plan["future_beacon_identity"]:
        raise LotteryError("future beacon round or identity is not the frozen plan value")
    seed = derive_commit_reveal_seed(
        frozen_plan,
        dev_seed=dev_seed,
        registrar_seed=registrar_seed,
        future_beacon_sha256=beacon,
    )
    accepted = sorted(entry["archive_sha256"] for entry in frozen_ledger["entries"] if entry["decision"] == "ACCEPTED")
    archive_to_family = population["family_report"]["archive_to_family"]
    selected_family_strata: dict[str, str] = {}
    for stratum in population["ordered_strata"]:
        stratum_id = stratum["stratum_id"]
        families = stratum["family_ids"]
        ranked_families = sorted(families, key=lambda family: (_lottery_rank(seed, f"family:{stratum_id}", family), family))
        for family in ranked_families[: frozen_plan["target_population"]["families_per_stratum"]]:
            selected_family_strata[family] = stratum_id
    if len(selected_family_strata) != frozen_plan["target_population"]["selected_families"]:
        raise LotteryError("the frozen stratum lottery did not select exactly 20 families")
    selected: list[str] = []
    selected_family_archives: list[dict[str, str]] = []
    for family in sorted(selected_family_strata):
        family_archives = [archive for archive in accepted if archive_to_family[archive] == family]
        ranked_archives = sorted(family_archives, key=lambda archive: (_lottery_rank(seed, f"archive:{family}", archive), archive))
        if not ranked_archives:
            raise LotteryError("selected family has no accepted archive")
        selected_archive = ranked_archives[0]
        selected.append(selected_archive)
        selected_family_archives.append({"derived_family_sha256": family, "archive_sha256": selected_archive})
    if len(selected) != len(set(selected)) or len(selected) != frozen_plan["target_population"]["selected_archives"]:
        raise LotteryError("lottery selected an archive more than once")
    activation_order = sorted(selected, key=lambda archive: (_lottery_rank(seed, "activation", archive), archive))
    block_size = frozen_plan["target_population"]["archives_per_activation_block"]
    blocks = [
        {"block_id": f"activation-{index + 1}", "archive_sha256s": activation_order[offset : offset + block_size]}
        for index, offset in enumerate(range(0, len(activation_order), block_size))
    ]
    if len(blocks) != frozen_plan["target_population"]["activation_blocks"] or any(len(block["archive_sha256s"]) != block_size for block in blocks):
        raise LotteryError("activation blocks do not have the frozen four-by-five shape")
    core = {
        "schema": LOTTERY_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "plan_sha256": frozen_plan["content_sha256"],
        "intake_content_sha256": frozen_ledger["content_sha256"],
        "ancestry_dag_sha256": dag["content_sha256"],
        "future_beacon_sha256": beacon,
        "future_beacon_round": round_id,
        "future_beacon_identity": identity,
        "seed_sha256": seed,
        "lottery_algorithm": frozen_plan["lottery_algorithm"],
        "no_replacement": True,
        "accepted_archive_sha256s": accepted,
        "selected_family_ids": sorted(selected_family_strata),
        "ordered_family_ids": population["ordered_family_ids"],
        "ordered_strata": population["ordered_strata"],
        "family_earliest_registration_utc": population["family_earliest_registration_utc"],
        "selected_family_strata": dict(sorted(selected_family_strata.items())),
        "selected_family_archives": selected_family_archives,
        "selected_archive_sha256s": sorted(selected),
        "activation_blocks": blocks,
    }
    return {**core, "content_sha256": canonical_sha256(core)}


def validate_roster_replay(
    plan: object,
    ledger: object,
    ancestry_dag: object,
    replay: object,
    *,
    dev_seed: str,
    registrar_seed: str,
) -> dict[str, Any]:
    raw = _exact(replay, _LOTTERY_FIELDS, label="roster replay", error=LotteryError)
    _reject_forbidden(raw, error=LotteryError)
    expected = replay_roster_lottery(
        plan,
        ledger,
        ancestry_dag,
        raw["future_beacon_sha256"],
        dev_seed=dev_seed,
        registrar_seed=registrar_seed,
        future_beacon_round=raw["future_beacon_round"],
        future_beacon_identity=raw["future_beacon_identity"],
    )
    if dict(raw) != expected:
        raise LotteryError("roster replay is not the exact deterministic result")
    return expected


def verify_recruitment(
    plan: object,
    ledger: object,
    ancestry_dag: object,
    replay: object | None = None,
    *,
    dev_seed: str | None = None,
    registrar_seed: str | None = None,
) -> dict[str, Any]:
    result = validate_recruitment_population(plan, ledger, ancestry_dag)
    if replay is None:
        result["roster_replay"] = None
    else:
        if dev_seed is None or registrar_seed is None:
            raise LotteryError("explicit dev_seed and registrar_seed reveals are required")
        result["roster_replay"] = validate_roster_replay(
            plan,
            ledger,
            ancestry_dag,
            replay,
            dev_seed=dev_seed,
            registrar_seed=registrar_seed,
        )
    return result


# Concise aliases for callers using audit/derive vocabulary.
audit_ancestry = validate_ancestry_dag
derive_families = derive_ancestry_families
validate_ancestry_manifest = validate_ancestry_dag
build_roster_replay = replay_roster_lottery
validate_roster = validate_roster_replay


__all__ = [
    "ANCESTRY_SCHEMA",
    "FAMILY_REPORT_SCHEMA",
    "GLOBAL_ANCESTRY_DAG_SCHEMA",
    "INTAKE_ENTRY_SCHEMA",
    "INTAKE_LEDGER_SCHEMA",
    "LOTTERY_SCHEMA",
    "PLAN_SCHEMA",
    "PROTOCOL_ID",
    "AncestryError",
    "IntakeError",
    "LotteryError",
    "PlanError",
    "RecruitmentError",
    "append_intake_entry",
    "audit_ancestry",
    "build_ancestry_dag",
    "build_intake_ledger",
    "build_recruitment_plan",
    "build_roster_replay",
    "canonical_json_bytes",
    "canonical_sha256",
    "classify_intake_candidate",
    "close_intake",
    "commit_recruitment_seed",
    "derive_ancestry_families",
    "derive_commit_reveal_seed",
    "derive_families",
    "replay_roster_lottery",
    "validate_ancestry_dag",
    "validate_ancestry_manifest",
    "validate_intake_ledger",
    "validate_recruitment_plan",
    "validate_recruitment_plan_envelope",
    "validate_recruitment_population",
    "validate_roster",
    "validate_roster_replay",
    "verify_recruitment",
]
