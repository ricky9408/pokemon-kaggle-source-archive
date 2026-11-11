"""Exact, offline V2 replay/builder for the generated C++ RNG trace contract.

This is conformance code only.  It neither proves engine integration nor grants
any campaign, holdout, agent-modification, or upload authority.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from .canonical_trace_codec import canonical_cbor_encode
from .rng_seed_protocol import SeedMaterial


BRANCH_TRACE_SCHEMA = "eval.v6.3.1.rng-branch-trace.v2"
EVENT_CORE_VERSION = 2
RAW_KIND, BOUNDED_KIND, SHUFFLE_KIND = 1, 2, 3
RAW_DRAW_ALGORITHM_ID = "V631/SHA256-CBOR-COUNTER-RAW-UINT64/V2"
BOUNDED_SAMPLING_ALGORITHM_ID = "V631/UINT64-REJECTION-MODULO/V2"
SHUFFLE_ALGORITHM_ID = "V631/FISHER-YATES-UINT64-REJECTION/V2"
SHUFFLE_ORIENTATION = "output[position]=input[permutation[position]]"
STREAM_DOMAINS = ("SETUP", "SHUFFLE", "COIN", "SEARCH", "RANDOM_SELECTION")
NO_UPLOAD = "NO_UPLOAD"
UINT64_MAX = (1 << 64) - 1
INT64_MIN, INT64_MAX = -(1 << 63), (1 << 63) - 1
ZERO_ROOT = bytes(32)

_ROOT_BRANCH_DOMAIN = b"V631/RNG/SEARCH-BRANCH-ROOT-NEUTRAL/V2"
_SEMANTIC_REQUEST_DOMAIN = b"V631/RNG/SEARCH-SEMANTIC-REQUEST/V2"
_CHILD_BRANCH_DOMAIN = b"V631/RNG/SEARCH-BRANCH-CHILD-NEUTRAL/V2"
_PUBLIC_BRANCH_DOMAIN = b"V631/RNG/SEARCH-BRANCH-PUBLIC/V2"
_BRANCH_SEED_DOMAIN = b"V631/RNG/SEARCH-BRANCH-SEED/V2"
_BRANCH_STREAM_ID_DOMAIN = b"V631/RNG/SEARCH-BRANCH-STREAM-ID/V2"
_BRANCH_STREAM_COMMITMENT_DOMAIN = b"V631/RNG/SEARCH-BRANCH-STREAM-COMMITMENT/V2"
_SESSION_HEADER_DOMAIN = b"V631/RNG/SESSION-HEADER/V2"
_GENESIS_DOMAIN = b"V631/RNG/BRANCH/GENESIS/V2"
_OPERATION_DOMAIN = b"V631/RNG/OPERATION/V2"
_EVENT_DOMAIN = b"V631/RNG/EVENT/V2"
_BRANCH_ROOT_DOMAIN = b"V631/RNG/BRANCH/ROOT/V2"
_BRANCH_ENVELOPE_DOMAIN = b"V631/RNG/BRANCH/ENVELOPE/V2"
_SESSION_ROOT_DOMAIN = b"V631/RNG/SESSION/ROOT/V2"
_RAW_DOMAIN = b"V631/RNG/RAW-UINT64"
_SEQUENCE_DOMAIN = b"V631/SEQUENCE"
_PERMUTATION_DOMAIN = b"V631/SHUFFLE/PERMUTATION"
_GAME_DOMAIN = b"V631/GAME"
_CARD_DOMAIN = b"V631/CARD-INSTANCE"

# Public names make the frozen C++ KDF/domain surface directly inspectable.
ROOT_BRANCH_NEUTRAL_DOMAIN = _ROOT_BRANCH_DOMAIN
SEMANTIC_REQUEST_DOMAIN = _SEMANTIC_REQUEST_DOMAIN
CHILD_BRANCH_NEUTRAL_DOMAIN = _CHILD_BRANCH_DOMAIN
PUBLIC_BRANCH_DOMAIN = _PUBLIC_BRANCH_DOMAIN
BRANCH_SEED_DOMAIN = _BRANCH_SEED_DOMAIN
BRANCH_STREAM_ID_DOMAIN = _BRANCH_STREAM_ID_DOMAIN
BRANCH_STREAM_COMMITMENT_DOMAIN = _BRANCH_STREAM_COMMITMENT_DOMAIN
SESSION_HEADER_DOMAIN = _SESSION_HEADER_DOMAIN
BRANCH_GENESIS_DOMAIN = _GENESIS_DOMAIN
OPERATION_DOMAIN = _OPERATION_DOMAIN
EVENT_DOMAIN = _EVENT_DOMAIN
BRANCH_ROOT_DOMAIN = _BRANCH_ROOT_DOMAIN
BRANCH_ENVELOPE_DOMAIN = _BRANCH_ENVELOPE_DOMAIN
SESSION_ROOT_DOMAIN = _SESSION_ROOT_DOMAIN
RAW_DRAW_DOMAIN = _RAW_DOMAIN
SEQUENCE_ROOT_DOMAIN = _SEQUENCE_DOMAIN
PERMUTATION_ROOT_DOMAIN = _PERMUTATION_DOMAIN


class RngBranchTraceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> RngBranchTraceError:
    return RngBranchTraceError(code, message)


def _hash(domain: bytes, value: Any) -> bytes:
    return sha256(domain + canonical_cbor_encode(value)).digest()


def _root(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", f"{label} must be exactly 32 bytes")
    return value


def _u64(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", f"{label} must be a non-boolean uint64")
    return value


def _s64(value: Any, label: str) -> int:
    if type(value) is not int or not INT64_MIN <= value <= INT64_MAX:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", f"{label} must be a non-boolean int64")
    return value


def _bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", f"{label} must be a boolean")
    return value


def _text(
    value: Any,
    label: str,
    *,
    nonempty: bool = False,
    ascii_only: bool = False,
) -> str:
    if type(value) is not str or (nonempty and not value):
        qualifier = "non-empty " if nonempty else ""
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", f"{label} must be {qualifier}text")
    if ascii_only and not value.isascii():
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", f"{label} must be ASCII text")
    return value


def _domain(value: Any) -> str:
    if type(value) is not str or value not in STREAM_DOMAINS:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "RNG stream domain is not one of the five frozen domains")
    return value


def _site(value: Any) -> bytes:
    return _root(value, "call_site_id")


def _ids(value: Any, label: str, *, unique: bool = False) -> list[bytes]:
    if type(value) is not list:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", f"{label} must be a list")
    result = [_root(item, label) for item in value]
    if unique and len(result) != len(set(result)):
        raise _fail("BRANCH_TRACE_REFERENCE_REUSE", f"{label} contains a reused identifier")
    return result


def _threshold(upper: Any) -> int:
    upper = _u64(upper, "exclusive_upper_bound")
    if upper == 0:
        raise _fail("BRANCH_TRACE_REJECTION_MISMATCH", "exclusive_upper_bound must be positive")
    return ((1 << 64) - upper) % upper


def session_header_hash(seed_material: SeedMaterial) -> bytes:
    if type(seed_material) is not SeedMaterial:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "seed_material must be SeedMaterial")
    return _hash(_SESSION_HEADER_DOMAIN, [
        BRANCH_TRACE_SCHEMA,
        seed_material.schedule_context_root(),
        seed_material.evaluator_secret_commitment,
        seed_material.run_commitment(),
    ])


def derive_root_neutral_branch_id(seed_material: SeedMaterial, request_ordinal: int = 0) -> bytes:
    if type(seed_material) is not SeedMaterial:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "seed_material must be SeedMaterial")
    return _hash(_ROOT_BRANCH_DOMAIN, [seed_material.schedule_context_root(), _u64(request_ordinal, "request_ordinal")])


def derive_semantic_request_root(operation: str, arguments: list[int]) -> bytes:
    if type(operation) is not str or not operation or not operation.isascii():
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "semantic operation must be non-empty ASCII")
    if type(arguments) is not list:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "semantic arguments must be a list")
    return _hash(_SEMANTIC_REQUEST_DOMAIN, [operation, [_s64(item, "semantic argument") for item in arguments]])


def derive_child_neutral_branch_id(
    seed_material: SeedMaterial,
    parent_neutral_branch_id: bytes,
    semantic_request_root: bytes,
    request_ordinal: int,
) -> bytes:
    if type(seed_material) is not SeedMaterial:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "seed_material must be SeedMaterial")
    return _hash(_CHILD_BRANCH_DOMAIN, [
        seed_material.schedule_context_root(),
        _root(parent_neutral_branch_id, "parent_neutral_branch_id"),
        _root(semantic_request_root, "semantic_request_root"),
        _u64(request_ordinal, "request_ordinal"),
    ])


def derive_public_branch_id(seed_material: SeedMaterial, neutral_branch_id: bytes) -> bytes:
    if type(seed_material) is not SeedMaterial:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "seed_material must be SeedMaterial")
    return _hash(_PUBLIC_BRANCH_DOMAIN, [seed_material.run_commitment(), _root(neutral_branch_id, "neutral_branch_id")])


def derive_operation_id(header: bytes, public_branch: bytes, sequence: int, kind: int, site: bytes) -> bytes:
    return _hash(_OPERATION_DOMAIN, [
        _root(header, "session_header_hash"), _root(public_branch, "public_branch_id"),
        _u64(sequence, "local_sequence"), _u64(kind, "event_kind"), _site(site),
    ])


def game_id(seed_material: SeedMaterial) -> bytes:
    return sha256(
        _GAME_DOMAIN + seed_material.model_root + seed_material.population_root
        + seed_material.candidate_archive_sha256 + seed_material.control_archive_sha256
        + seed_material.common_seed_id.to_bytes(2, "big") + bytes((seed_material.candidate_seat,))
    ).digest()


def card_instance_id(seed_material: SeedMaterial, card_index: int) -> bytes:
    if type(card_index) is not int or not 3 <= card_index <= 122:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "card_index must identify a physical game card")
    owner = 0 if card_index <= 62 else 1
    position = card_index - (3 if owner == 0 else 63)
    return sha256(_CARD_DOMAIN + game_id(seed_material) + bytes((owner,)) + position.to_bytes(2, "big")).digest()


def sequence_root(card_ids: list[bytes]) -> bytes:
    return _hash(_SEQUENCE_DOMAIN, _ids(card_ids, "card_ids", unique=True))


def permutation_root(permutation: list[int]) -> bytes:
    if type(permutation) is not list:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "permutation must be a list")
    return _hash(_PERMUTATION_DOMAIN, [_u64(item, "permutation index") for item in permutation])


def cpp_shuffle_card_ids(seed_material: SeedMaterial, card_indices: list[int]) -> list[bytes]:
    """Convert the C++ physical-card vector input to its full V2 card IDs."""
    if type(card_indices) is not list:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "card_indices must be a list")
    ids = [card_instance_id(seed_material, item) for item in card_indices]
    if len(ids) != len(set(ids)):
        raise _fail("BRANCH_TRACE_REFERENCE_REUSE", "shuffle input repeats a physical card")
    return ids


@dataclass(slots=True)
class _Branch:
    depth: int
    neutral: bytes
    public: bytes
    root_branch: bool
    parent: bytes
    operation: str
    arguments: list[int]
    semantic_root: bytes
    request_ordinal: int
    counters: dict[str, int] = field(default_factory=lambda: dict.fromkeys(STREAM_DOMAINS, 0))
    events: list[list[Any]] = field(default_factory=list)
    lifecycle: str = "CREATED"
    sealed: bool = False
    semantic_counts: dict[bytes, int] = field(default_factory=dict)


class RngBranchTraceSession:
    """Strict local builder matching the generated C++ search-branch contract."""

    def __init__(self, seed_material: SeedMaterial) -> None:
        if type(seed_material) is not SeedMaterial:
            raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "seed_material must be SeedMaterial")
        self.seed_material = seed_material
        self.header = session_header_hash(seed_material)
        self._branches: dict[bytes, _Branch] = {}
        self._completed: list[_Branch] = []
        self._authoritative = _Branch(
            0,
            ZERO_ROOT,
            ZERO_ROOT,
            False,
            ZERO_ROOT,
            "AUTHORITATIVE",
            [],
            ZERO_ROOT,
            0,
            lifecycle="AUTHORITATIVE",
        )
        self._active: _Branch | None = None
        self._next_root_ordinal = 0
        self._next_response_sequence = 0

    @property
    def session_header_hash(self) -> bytes:
        return self.header

    def make_search_root(self) -> bytes:
        ordinal = self._next_root_ordinal
        neutral = derive_root_neutral_branch_id(self.seed_material, ordinal)
        self._next_root_ordinal += 1
        return self._create_branch(0, neutral, True, ZERO_ROOT, "ROOT", [], ZERO_ROOT, ordinal)

    @property
    def root_branch_id(self) -> bytes:
        # Kept as a convenient V2 root creation hook; it never reuses a root.
        return self.make_search_root()

    def fork_search_step(self, parent: bytes, arguments: list[int]) -> bytes:
        return self._fork(parent, "STEP", arguments)

    def fork_search_shuffle(self, parent: bytes, player_role: int) -> bytes:
        if type(player_role) is not int or player_role not in (0, 1):
            raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "search shuffle role must be zero or one")
        return self._fork(parent, "SHUFFLE", [player_role])

    def _fork(self, parent_id: bytes, operation: str, arguments: list[int]) -> bytes:
        parent = self._branch(parent_id)
        if parent.lifecycle != "COMMITTED":
            raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "a child requires a committed parent branch")
        semantic = derive_semantic_request_root(operation, arguments)
        ordinal = parent.semantic_counts.get(semantic, 0)
        parent.semantic_counts[semantic] = ordinal + 1
        neutral = derive_child_neutral_branch_id(self.seed_material, parent.neutral, semantic, ordinal)
        return self._create_branch(parent.depth + 1, neutral, False, parent.neutral, operation, arguments, semantic, ordinal)

    def _create_branch(self, depth: int, neutral: bytes, root: bool, parent: bytes, operation: str, arguments: list[int], semantic: bytes, ordinal: int) -> bytes:
        if neutral in self._branches:
            raise _fail("BRANCH_TRACE_DUPLICATE_ID", "neutral branch ID is already live")
        branch = _Branch(depth, neutral, derive_public_branch_id(self.seed_material, neutral), root, parent, operation, list(arguments), semantic, ordinal)
        self._branches[neutral] = branch
        return neutral

    def activate_search_branch(self, branch_id: bytes) -> None:
        if self._active is not None:
            raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "search scopes cannot be nested")
        branch = self._branch(branch_id)
        if branch.lifecycle != "CREATED":
            raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "branch cannot be activated twice")
        branch.lifecycle, self._active = "ACTIVE", branch

    def commit_search_branch(self, branch_id: bytes) -> None:
        self._resolve(branch_id, "COMMITTED")

    def abort_search_branch(self, branch_id: bytes) -> None:
        self._resolve(branch_id, "ABORTED")

    def _resolve(self, branch_id: bytes, lifecycle: str) -> None:
        branch = self._branch(branch_id)
        if self._active is not branch or branch.lifecycle != "ACTIVE":
            raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "branch resolution is out of lifecycle order")
        branch.lifecycle, branch.sealed, self._active = lifecycle, True, None
        self._completed.append(branch)

    def release_search_branch(self, branch_id: bytes) -> None:
        branch = self._branch(branch_id)
        if branch.lifecycle not in ("COMMITTED", "ABORTED") or self._active is branch:
            raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "branch must resolve before release")
        del self._branches[branch.neutral]

    def record_raw(self, domain: str, call_site_id: bytes) -> list[Any]:
        branch = self._current_branch()
        domain, site = _domain(domain), _site(call_site_id)
        before = branch.counters[domain]
        if before == UINT64_MAX:
            raise _fail("BRANCH_TRACE_ORDER_INVALID", "stream counter is exhausted")
        seed, stream_id, commitment = _branch_stream_material(self.seed_material, branch.neutral, branch.public, domain)
        raw = _hash(_RAW_DOMAIN, [seed, before])[:8]
        payload = [domain, branch.neutral, branch.public, stream_id, commitment, before, before + 1, raw, site]
        event = self._append(branch, RAW_KIND, site, payload)
        branch.counters[domain] = before + 1
        return event

    def record_bounded(self, domain: str, exclusive_upper_bound: int, call_site_id: bytes) -> list[Any]:
        branch = self._current_branch()
        domain, site = _domain(domain), _site(call_site_id)
        upper, threshold, before = _u64(exclusive_upper_bound, "exclusive_upper_bound"), None, branch.counters[domain]
        threshold = _threshold(upper)
        raw_events: list[list[Any]] = []
        while True:
            raw_event = self.record_raw(domain, site)
            raw_events.append(raw_event)
            if int.from_bytes(raw_event[0][5][7], "big") >= threshold:
                break
        values = [int.from_bytes(item[0][5][7], "big") for item in raw_events]
        raw_ids = [item[0][4] for item in raw_events]
        flags = [False] * (len(values) - 1) + [True]
        seed, stream_id, _commitment = _branch_stream_material(self.seed_material, branch.neutral, branch.public, domain)
        del seed
        payload = [BOUNDED_SAMPLING_ALGORITHM_ID, domain, branch.neutral, branch.public, stream_id, upper, threshold, raw_ids, values[:-1], flags, values[-1], values[-1] % upper, before, branch.counters[domain], site]
        return self._append(branch, BOUNDED_KIND, site, payload)

    def record_shuffle(self, domain: str, input_card_ids: list[bytes], call_site_id: bytes, zone_id: str) -> tuple[list[bytes], list[Any]]:
        branch = self._current_branch()
        domain, site = _domain(domain), _site(call_site_id)
        if type(zone_id) is not str or not zone_id:
            raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "shuffle zone ID is required")
        inputs = _ids(input_card_ids, "input_card_ids", unique=True)
        permutation = list(range(len(inputs)))
        bounded_ids: list[bytes] = []
        for remaining in range(len(inputs), 1, -1):
            bounded = self.record_bounded(domain, remaining, site)
            selected = bounded[0][5][11]
            bounded_ids.append(bounded[0][4])
            permutation[remaining - 1], permutation[selected] = permutation[selected], permutation[remaining - 1]
        outputs = [inputs[position] for position in permutation]
        _seed, stream_id, _commitment = _branch_stream_material(self.seed_material, branch.neutral, branch.public, domain)
        payload = [SHUFFLE_ALGORITHM_ID, domain, branch.neutral, branch.public, stream_id, zone_id, inputs, sequence_root(inputs), bounded_ids, SHUFFLE_ORIENTATION, permutation, permutation_root(permutation), outputs, sequence_root(outputs), site]
        return outputs, self._append(branch, SHUFFLE_KIND, site, payload)

    def record_shuffle_from_cpp_indices(self, domain: str, card_indices: list[int], call_site_id: bytes, zone_id: str) -> tuple[list[int], list[Any]]:
        inputs = cpp_shuffle_card_ids(self.seed_material, card_indices)
        outputs, event = self.record_shuffle(domain, inputs, call_site_id, zone_id)
        by_id = dict(zip(inputs, card_indices))
        return [by_id[item] for item in outputs], event

    def _append(self, branch: _Branch, kind: int, site: bytes, payload: list[Any]) -> list[Any]:
        sequence = len(branch.events)
        operation = derive_operation_id(self.header, branch.public, sequence, kind, site)
        previous = branch.events[-1][1] if branch.events else _genesis(self.header, branch.public)
        core = [EVENT_CORE_VERSION, sequence, kind, previous, operation, payload]
        event_hash = sha256(_EVENT_DOMAIN + self.header + canonical_cbor_encode(core)).digest()
        event = [core, event_hash]
        branch.events.append(event)
        return deepcopy(event)

    def branch_envelopes(self) -> list[list[Any]]:
        branches = [self._authoritative, *self._completed]
        return [_branch_envelope(self.header, branch) for branch in sorted(branches, key=lambda item: (item.depth, item.neutral))]

    def seal(self) -> list[Any]:
        if self._active is not None or any(not branch.sealed for branch in self._branches.values()):
            raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "unresolved search branch blocks the response checkpoint")
        branches = self.branch_envelopes()
        envelope = [EVENT_CORE_VERSION, self._next_response_sequence, self.header, branches]
        self._next_response_sequence += 1
        return envelope

    def session_root(self, envelope: list[Any] | None = None) -> bytes:
        envelope = self.seal() if envelope is None else envelope
        return _hash(_SESSION_ROOT_DOMAIN, envelope)

    def zero_authority_report(self) -> dict[str, Any]:
        return {"authority": NO_UPLOAD, "calibration_upload_authorized": False, "production_upload_authorized": False, "sealed_holdout_access_authorized": False, "agent_modification_authorized": False, "compiler_completeness_claimed": False, "independent_ab_authority_claimed": False}

    def _branch(self, branch_id: bytes) -> _Branch:
        branch = self._branches.get(_root(branch_id, "neutral_branch_id"))
        if branch is None:
            raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "branch is foreign, released, or uninitialized")
        return branch

    def _current_branch(self) -> _Branch:
        if self._active is None:
            return self._authoritative
        if self._active.lifecycle != "ACTIVE":
            raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "active search branch lifecycle is invalid")
        return self._active


def _branch_stream_material(material: SeedMaterial, neutral: bytes, public: bytes, domain: str) -> tuple[bytes, bytes, bytes]:
    if neutral == ZERO_ROOT and public == ZERO_ROOT:
        return (
            material.stream_seed(domain),
            material.stream_id(domain),
            material.stream_seed_commitment(domain),
        )
    branch_seed = _hash(_BRANCH_SEED_DOMAIN, [material.master_seed(), neutral])
    seed = _hash(b"V631/RNG/STREAM-SEED/V2", [branch_seed, domain])
    stream_id = _hash(_BRANCH_STREAM_ID_DOMAIN, [material.run_commitment(), public, domain])
    commitment = _hash(_BRANCH_STREAM_COMMITMENT_DOMAIN, [material.run_commitment(), public, domain, seed])
    return seed, stream_id, commitment


def _genesis(header: bytes, public: bytes) -> bytes:
    return _hash(_GENESIS_DOMAIN, [_root(header, "session_header_hash"), _root(public, "public_branch_id")])


def _chain_root(header: bytes, branch: _Branch, final_hash: bytes) -> bytes:
    return _hash(_BRANCH_ROOT_DOMAIN, [header, branch.depth, branch.neutral, branch.public, len(branch.events), final_hash])


def _branch_envelope(header: bytes, branch: _Branch) -> list[Any]:
    if branch.lifecycle != "AUTHORITATIVE" and not branch.sealed:
        raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "only resolved branches have envelopes")
    disposition = 0 if branch.lifecycle == "AUTHORITATIVE" else 1 if branch.lifecycle == "COMMITTED" else 2
    final_hash = branch.events[-1][1] if branch.events else _genesis(header, branch.public)
    return [
        EVENT_CORE_VERSION,
        branch.depth,
        branch.neutral,
        branch.public,
        branch.root_branch,
        branch.parent,
        branch.operation,
        list(branch.arguments),
        branch.semantic_root,
        branch.request_ordinal,
        disposition,
        len(branch.events),
        deepcopy(branch.events),
        _chain_root(header, branch, final_hash),
    ]


def branch_envelope_root(branch_envelope: list[Any]) -> bytes:
    return _hash(_BRANCH_ENVELOPE_DOMAIN, _validate_branch_envelope(branch_envelope)[0])


def session_envelope_root(session_envelope: list[Any]) -> bytes:
    _validate_session_envelope(session_envelope)
    return _hash(_SESSION_ROOT_DOMAIN, session_envelope)


def replay_session(session_envelope: Any, seed_material: SeedMaterial) -> dict[str, Any]:
    """Replay all V2 evidence embedded in one exact C++ session envelope."""
    header, branches = _validate_session_envelope(session_envelope)
    if header != session_header_hash(seed_material):
        raise _fail("BRANCH_TRACE_KDF_MISMATCH", "session header does not match the revealed seed material")
    known: dict[bytes, tuple[list[Any], list[Any]]] = {}
    claimed_raw: set[bytes] = set()
    claimed_bounded: set[bytes] = set()
    seen_operations: set[bytes] = set()
    prior_branches: dict[bytes, list[Any]] = {}
    for branch in branches:
        _replay_branch(header, seed_material, branch, known, claimed_raw, claimed_bounded, seen_operations, prior_branches)
        prior_branches[branch[2]] = branch
    return {"authority": NO_UPLOAD, "calibration_upload_authorized": False, "production_upload_authorized": False, "sealed_holdout_access_authorized": False, "agent_modification_authorized": False, "compiler_completeness_claimed": False, "independent_ab_authority_claimed": False, "session_root": session_envelope_root(session_envelope)}


def _validate_session_envelope(value: Any) -> tuple[bytes, list[list[Any]]]:
    if type(value) is not list or len(value) != 4 or value[0] != EVENT_CORE_VERSION:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "session envelope must be the exact C++ four-field vector")
    _u64(value[1], "response_sequence")
    header = _root(value[2], "session_header_hash")
    if type(value[3]) is not list:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "session branches must be a list")
    branches = [_validate_branch_envelope(item)[0] for item in value[3]]
    if branches != sorted(branches, key=lambda item: (item[1], item[2])):
        raise _fail("BRANCH_TRACE_ORDER_INVALID", "session branches are not sorted by depth and neutral ID")
    if len({(item[1], item[2]) for item in branches}) != len(branches):
        raise _fail("BRANCH_TRACE_DUPLICATE_ID", "session has duplicate branch identities")
    authoritative = [item for item in branches if item[10] == 0]
    if len(authoritative) != 1:
        raise _fail(
            "BRANCH_TRACE_REFERENCE_INVALID",
            "session must contain exactly one authoritative snapshot",
        )
    search = [item for item in branches if item[10] != 0]
    if len({item[3] for item in search}) != len(search):
        raise _fail("BRANCH_TRACE_DUPLICATE_ID", "session reuses a public branch ID")
    root_ordinals = sorted(item[9] for item in search if item[4])
    if root_ordinals != list(range(len(root_ordinals))):
        raise _fail(
            "BRANCH_TRACE_ORDER_INVALID",
            "root request ordinals are not contiguous from zero",
        )
    child_ordinals: dict[tuple[bytes, bytes], list[int]] = {}
    for item in search:
        if not item[4]:
            child_ordinals.setdefault((item[5], item[8]), []).append(item[9])
    if any(
        sorted(ordinals) != list(range(len(ordinals)))
        for ordinals in child_ordinals.values()
    ):
        raise _fail(
            "BRANCH_TRACE_ORDER_INVALID",
            "child request ordinals are not contiguous per parent and semantic request",
        )
    return header, branches


def _validate_branch_envelope(value: Any) -> tuple[list[Any], bytes]:
    if type(value) is not list or len(value) != 14 or value[0] != EVENT_CORE_VERSION:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "branch envelope must be the exact C++ 14-field vector")
    version, depth, neutral, public, root_branch, parent, operation, arguments, semantic, ordinal, disposition, count, events, chain = value
    del version
    _u64(depth, "branch_depth"); neutral = _root(neutral, "neutral_branch_id"); public = _root(public, "public_branch_id")
    _bool(root_branch, "root_branch")
    _text(operation, "branch operation", ascii_only=True)
    if type(arguments) is not list:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "branch metadata is malformed")
    [_s64(item, "branch argument") for item in arguments]
    _root(parent, "parent_neutral_branch_id"); semantic = _root(semantic, "semantic_request_root")
    _u64(ordinal, "request_ordinal"); count = _u64(count, "event_count"); _root(chain, "event_chain_root")
    if type(events) is not list:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "embedded branch events must be a list")
    if count != len(events):
        raise _fail(
            "BRANCH_TRACE_ROOT_MISMATCH",
            "branch event count is not sealed by its envelope",
        )
    _u64(disposition, "branch_disposition")
    if disposition not in (0, 1, 2):
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "branch disposition is invalid")
    if root_branch:
        if depth != 0 or parent != ZERO_ROOT or operation != "ROOT" or arguments or semantic != ZERO_ROOT or disposition not in (1, 2):
            raise _fail("BRANCH_TRACE_REFERENCE_INVALID", "root branch metadata is invalid")
    elif disposition == 0:
        if neutral != ZERO_ROOT or public != ZERO_ROOT or parent != ZERO_ROOT or operation != "AUTHORITATIVE" or arguments or semantic != ZERO_ROOT or depth != 0 or ordinal != 0:
            raise _fail("BRANCH_TRACE_REFERENCE_INVALID", "authoritative snapshot metadata is invalid")
    elif depth == 0 or parent == ZERO_ROOT or not operation or semantic != derive_semantic_request_root(operation, arguments):
        raise _fail("BRANCH_TRACE_REFERENCE_INVALID", "child branch metadata is invalid")
    return value, chain


def _replay_branch(header: bytes, material: SeedMaterial, branch: list[Any], known: dict[bytes, tuple[list[Any], list[Any]]], claimed_raw: set[bytes], claimed_bounded: set[bytes], seen_operations: set[bytes], prior: dict[bytes, list[Any]]) -> None:
    _, depth, neutral, public, root, parent, operation, arguments, semantic, ordinal, disposition, count, events, supplied_chain = branch
    if root:
        expected_neutral = derive_root_neutral_branch_id(material, ordinal)
    elif disposition == 0:
        expected_neutral = expected_public = ZERO_ROOT
    else:
        parent_branch = prior.get(parent)
        if (
            parent_branch is None
            or parent_branch[10] != 1
            or depth != parent_branch[1] + 1
        ):
            raise _fail("BRANCH_TRACE_LIFECYCLE_INVALID", "child has no preceding committed parent")
        expected_neutral = derive_child_neutral_branch_id(material, parent, semantic, ordinal)
    if neutral != expected_neutral or (disposition != 0 and public != derive_public_branch_id(material, neutral)):
        raise _fail("BRANCH_TRACE_KDF_MISMATCH", "branch identity does not match V2 derivation")
    if count != len(events):
        raise _fail("BRANCH_TRACE_ROOT_MISMATCH", "branch event count is not sealed by its envelope")
    counters = dict.fromkeys(STREAM_DOMAINS, 0)
    previous = _genesis(header, public)
    for sequence, item in enumerate(events):
        if type(item) is not list or len(item) != 2 or type(item[0]) is not list:
            raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "event must be [core, event_hash]")
        core, event_hash = item
        if len(core) != 6 or core[0] != EVENT_CORE_VERSION:
            raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "event core has the wrong V2 shape")
        if (
            _u64(core[1], "local_sequence") != sequence
            or _root(core[3], "previous_event_hash") != previous
        ):
            raise _fail("BRANCH_TRACE_ORDER_INVALID", "event core sequence or predecessor is invalid")
        kind, operation_id, payload = _u64(core[2], "event_kind"), _root(core[4], "operation_id"), core[5]
        if kind not in (RAW_KIND, BOUNDED_KIND, SHUFFLE_KIND) or operation_id in seen_operations:
            raise _fail("BRANCH_TRACE_DUPLICATE_ID", "event operation ID is invalid or reused")
        site = _payload_site(kind, payload)
        if operation_id != derive_operation_id(header, public, sequence, kind, site):
            raise _fail("BRANCH_TRACE_KDF_MISMATCH", "operation ID is not the derived V2 ID")
        expected_hash = sha256(_EVENT_DOMAIN + header + canonical_cbor_encode(core)).digest()
        if _root(event_hash, "event_hash") != expected_hash:
            raise _fail("BRANCH_TRACE_ROOT_MISMATCH", "event hash does not seal its canonical core")
        if kind == RAW_KIND:
            _replay_raw(material, neutral, public, payload, counters); known[operation_id] = (branch, payload)
        elif kind == BOUNDED_KIND:
            _replay_bounded(
                neutral,
                public,
                payload,
                known,
                claimed_raw,
                events[:sequence],
            )
            known[operation_id] = (branch, payload)
        else:
            _replay_shuffle(
                neutral,
                public,
                payload,
                known,
                claimed_bounded,
                events[:sequence],
            )
        seen_operations.add(operation_id); previous = event_hash
    record = _Branch(depth, neutral, public, root, parent, operation, arguments, semantic, ordinal, events=events)
    if supplied_chain != _chain_root(header, record, previous):
        raise _fail("BRANCH_TRACE_ROOT_MISMATCH", "event-chain root does not match the replay")


def _payload_site(kind: int, payload: Any) -> bytes:
    if type(payload) is not list or len(payload) != (9 if kind == 1 else 15):
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "event semantic payload has the wrong V2 arity")
    return _site(payload[-1])


def _replay_raw(material: SeedMaterial, neutral: bytes, public: bytes, payload: Any, counters: dict[str, int]) -> None:
    domain, stated_neutral, stated_public, stream_id, commitment, before, after, raw, _site_id = payload
    domain = _domain(domain)
    if stated_neutral != neutral or stated_public != public:
        raise _fail("BRANCH_TRACE_REFERENCE_INVALID", "raw branch IDs do not match its envelope")
    seed, expected_id, expected_commitment = _branch_stream_material(material, neutral, public, domain)
    if _root(stream_id, "stream_id") != expected_id or _root(commitment, "stream_commitment") != expected_commitment:
        raise _fail("BRANCH_TRACE_KDF_MISMATCH", "raw stream binding is invalid")
    if _u64(before, "counter_before") != counters[domain] or _u64(after, "counter_after") != before + 1 or type(raw) is not bytes or len(raw) != 8:
        raise _fail("BRANCH_TRACE_ORDER_INVALID", "raw counter span or bytes are invalid")
    if raw != _hash(_RAW_DOMAIN, [seed, before])[:8]:
        raise _fail("BRANCH_TRACE_RAW_MISMATCH", "raw output does not match the V2 KDF")
    counters[domain] = after


def _replay_bounded(
    neutral: bytes,
    public: bytes,
    payload: Any,
    known: dict[bytes, tuple[list[Any], list[Any]]],
    claimed: set[bytes],
    prior_events: list[list[Any]],
) -> None:
    algorithm, domain, stated_neutral, stated_public, stream_id, upper, threshold, raw_ids, rejected, flags, accepted, mapped, before, after, _site_id = payload
    domain = _domain(domain)
    _text(algorithm, "bounded algorithm", nonempty=True, ascii_only=True)
    _root(stated_neutral, "bounded neutral_branch_id")
    _root(stated_public, "bounded public_branch_id")
    stream_id = _root(stream_id, "bounded stream_id")
    upper = _u64(upper, "exclusive_upper_bound")
    threshold = _u64(threshold, "rejection_threshold")
    before = _u64(before, "bounded counter_before")
    after = _u64(after, "bounded counter_after")
    site = _site(_site_id)
    if type(rejected) is not list or type(flags) is not list:
        raise _fail(
            "BRANCH_TRACE_SCHEMA_INVALID",
            "bounded rejected values and acceptance flags must be lists",
        )
    rejected = [_u64(item, "rejected raw value") for item in rejected]
    flags = [_bool(item, "acceptance flag") for item in flags]
    accepted = _u64(accepted, "accepted raw value")
    mapped = _u64(mapped, "bounded mapped result")
    if (
        algorithm != BOUNDED_SAMPLING_ALGORITHM_ID
        or stated_neutral != neutral
        or stated_public != public
        or threshold != _threshold(upper)
    ):
        raise _fail("BRANCH_TRACE_REJECTION_MISMATCH", "bounded algorithm or binding is invalid")
    raw_ids = _ids(raw_ids, "raw_event_ids", unique=True)
    if not raw_ids or any(item in claimed for item in raw_ids):
        raise _fail("BRANCH_TRACE_REFERENCE_REUSE", "bounded sample reuses raw evidence")
    prior_operation_ids = [
        _root(item[0][4], "prior operation_id")
        for item in prior_events
        if type(item) is list
        and len(item) == 2
        and type(item[0]) is list
        and len(item[0]) == 6
    ]
    if (
        len(prior_operation_ids) != len(prior_events)
        or len(raw_ids) > len(prior_operation_ids)
        or prior_operation_ids[-len(raw_ids):] != raw_ids
    ):
        raise _fail(
            "BRANCH_TRACE_ORDER_INVALID",
            "bounded raw evidence is not the immediately preceding event span",
        )
    raws = [known.get(item) for item in raw_ids]
    if any(item is None for item in raws):
        raise _fail("BRANCH_TRACE_REFERENCE_INVALID", "bounded sample references missing raw evidence")
    raw_payloads = [item[1] for item in raws if item is not None]
    if any(
        item[0] != domain
        or item[1] != neutral
        or item[2] != public
        or item[3] != stream_id
        or item[8] != site
        for item in raw_payloads
    ):
        raise _fail("BRANCH_TRACE_REFERENCE_INVALID", "bounded raw evidence does not share its stream")
    values = [int.from_bytes(item[7], "big") for item in raw_payloads]
    if (
        any(value >= threshold for value in values[:-1])
        or values[-1] < threshold
        or rejected != values[:-1]
        or flags != [False] * (len(values) - 1) + [True]
        or accepted != values[-1]
        or mapped != values[-1] % upper
        or before != raw_payloads[0][5]
        or after != raw_payloads[-1][6]
    ):
        raise _fail("BRANCH_TRACE_REJECTION_MISMATCH", "bounded rejection transcript is invalid")
    claimed.update(raw_ids)


def _replay_shuffle(
    neutral: bytes,
    public: bytes,
    payload: Any,
    known: dict[bytes, tuple[list[Any], list[Any]]],
    claimed: set[bytes],
    prior_events: list[list[Any]],
) -> None:
    algorithm, domain, stated_neutral, stated_public, _stream_id, zone, inputs, input_root, bounded_ids, orientation, permutation, perm_root, outputs, output_root, _site_id = payload
    domain = _domain(domain)
    _text(algorithm, "shuffle algorithm", nonempty=True, ascii_only=True)
    _root(stated_neutral, "shuffle neutral_branch_id")
    _root(stated_public, "shuffle public_branch_id")
    stream_id = _root(_stream_id, "shuffle stream_id")
    _text(zone, "shuffle zone ID", nonempty=True)
    _text(orientation, "shuffle orientation", nonempty=True, ascii_only=True)
    input_root = _root(input_root, "input_sequence_root")
    perm_root = _root(perm_root, "permutation_root")
    output_root = _root(output_root, "output_sequence_root")
    site = _site(_site_id)
    inputs, outputs, bounded_ids = _ids(inputs, "input_card_ids", unique=True), _ids(outputs, "output_card_ids", unique=True), _ids(bounded_ids, "bounded_event_ids", unique=True)
    if (
        algorithm != SHUFFLE_ALGORITHM_ID
        or stated_neutral != neutral
        or stated_public != public
        or orientation != SHUFFLE_ORIENTATION
        or input_root != sequence_root(inputs)
        or output_root != sequence_root(outputs)
    ):
        raise _fail("BRANCH_TRACE_SHUFFLE_MISMATCH", "shuffle metadata or card roots are invalid")
    if any(item in claimed for item in bounded_ids):
        raise _fail("BRANCH_TRACE_REFERENCE_REUSE", "shuffle reuses bounded evidence")
    samples = [known.get(item) for item in bounded_ids]
    if any(item is None for item in samples):
        raise _fail("BRANCH_TRACE_REFERENCE_INVALID", "shuffle references missing bounded evidence")
    bounded = [item[1] for item in samples if item is not None]
    if (
        len(bounded) != max(0, len(inputs) - 1)
        or any(
            item[1] != domain
            or item[2] != neutral
            or item[3] != public
            or item[4] != stream_id
            or item[14] != site
            for item in bounded
        )
        or [item[5] for item in bounded] != list(range(len(inputs), 1, -1))
    ):
        raise _fail("BRANCH_TRACE_SHUFFLE_MISMATCH", "shuffle bounded schedule is not Fisher-Yates")
    if type(permutation) is not list:
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "shuffle permutation must be a list")
    permutation = [_u64(item, "permutation index") for item in permutation]
    if sorted(permutation) != list(range(len(inputs))) or perm_root != permutation_root(permutation):
        raise _fail("BRANCH_TRACE_SHUFFLE_MISMATCH", "shuffle permutation is invalid")
    prior_operation_ids = [
        _root(item[0][4], "prior operation_id")
        for item in prior_events
        if type(item) is list
        and len(item) == 2
        and type(item[0]) is list
        and len(item[0]) == 6
    ]
    if len(prior_operation_ids) != len(prior_events):
        raise _fail("BRANCH_TRACE_SCHEMA_INVALID", "prior event span is malformed")
    operation_positions = {
        operation_id: index
        for index, operation_id in enumerate(prior_operation_ids)
    }
    previous_bounded_position: int | None = None
    for bounded_id, bounded_payload in zip(bounded_ids, bounded):
        bounded_position = operation_positions.get(bounded_id)
        raw_ids = _ids(bounded_payload[7], "shuffle bounded raw_event_ids", unique=True)
        if (
            bounded_position is None
            or len(raw_ids) > bounded_position
            or prior_operation_ids[bounded_position - len(raw_ids):bounded_position]
            != raw_ids
            or (
                previous_bounded_position is not None
                and bounded_position - len(raw_ids) != previous_bounded_position + 1
            )
        ):
            raise _fail(
                "BRANCH_TRACE_ORDER_INVALID",
                "shuffle bounded evidence is not one contiguous event span",
            )
        previous_bounded_position = bounded_position
    if bounded_ids and previous_bounded_position != len(prior_events) - 1:
        raise _fail(
            "BRANCH_TRACE_ORDER_INVALID",
            "shuffle bounded evidence does not immediately precede the shuffle event",
        )
    expected = list(range(len(inputs)))
    for position, sample in zip(range(len(inputs) - 1, 0, -1), bounded):
        expected[position], expected[sample[11]] = expected[sample[11]], expected[position]
    if permutation != expected or outputs != [inputs[index] for index in permutation]:
        raise _fail("BRANCH_TRACE_SHUFFLE_MISMATCH", "shuffle output orientation is invalid")
    claimed.update(bounded_ids)


__all__ = [
    "BOUNDED_KIND", "BOUNDED_SAMPLING_ALGORITHM_ID", "BRANCH_ENVELOPE_DOMAIN", "BRANCH_GENESIS_DOMAIN", "BRANCH_ROOT_DOMAIN", "BRANCH_SEED_DOMAIN", "BRANCH_STREAM_COMMITMENT_DOMAIN", "BRANCH_STREAM_ID_DOMAIN", "BRANCH_TRACE_SCHEMA", "CHILD_BRANCH_NEUTRAL_DOMAIN", "EVENT_CORE_VERSION", "EVENT_DOMAIN", "NO_UPLOAD", "OPERATION_DOMAIN", "PERMUTATION_ROOT_DOMAIN", "PUBLIC_BRANCH_DOMAIN", "RAW_DRAW_ALGORITHM_ID", "RAW_DRAW_DOMAIN", "RAW_KIND", "ROOT_BRANCH_NEUTRAL_DOMAIN", "RngBranchTraceError", "RngBranchTraceSession", "SEMANTIC_REQUEST_DOMAIN", "SEQUENCE_ROOT_DOMAIN", "SESSION_HEADER_DOMAIN", "SESSION_ROOT_DOMAIN", "SHUFFLE_ALGORITHM_ID", "SHUFFLE_KIND", "SHUFFLE_ORIENTATION", "STREAM_DOMAINS", "branch_envelope_root", "card_instance_id", "cpp_shuffle_card_ids", "derive_child_neutral_branch_id", "derive_operation_id", "derive_public_branch_id", "derive_root_neutral_branch_id", "derive_semantic_request_root", "game_id", "permutation_root", "replay_session", "sequence_root", "session_envelope_root", "session_header_hash",
]
