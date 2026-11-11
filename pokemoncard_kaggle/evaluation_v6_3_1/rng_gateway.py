"""Zero-authority reference contract for the v6.3.1 deterministic RNG gateway.

This is an offline Python reference for Package 3.  It specifies rooted seed
material, named streams, recorded raw uint64 draws, unbiased rejection
sampling, and Fisher-Yates evidence.  It neither scans C++ nor proves that all
engine entropy sites were discovered; a coverage manifest is only an explicit
inventory claim and can never authorize an upload or campaign action.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import re
from types import MappingProxyType
from typing import Any

from .canonical_trace_codec import canonical_cbor_encode
from .canonical_trace_replay import (
    RNG_BOUNDED_SAMPLE,
    RNG_DRAW,
    RNG_STREAM_BOUND,
    SHUFFLE_APPLIED,
)
from .common import canonical_sha256, freeze, zero_authority
from .rng_seed_protocol import SeedMaterial


RNG_GATEWAY_SCHEMA = "eval.v6.3.1.rng-gateway-reference.v1"
RNG_COVERAGE_SCHEMA = "eval.v6.3.1.rng-gateway-coverage.v1"
RNG_COVERAGE_MODE = "TEST_ONLY/OFFLINE_REFERENCE_CONTRACT"
RAW_DRAW_ALGORITHM_ID = "V631/SHA256-CBOR-COUNTER-RAW-UINT64/V2"
BOUNDED_SAMPLING_ALGORITHM_ID = "V631/UINT64-REJECTION-MODULO/V2"
SHUFFLE_ALGORITHM_ID = "V631/FISHER-YATES-UINT64-REJECTION/V2"
RAW_DRAW_DOMAIN = b"V631/RNG/RAW-UINT64"

STREAM_SETUP = "SETUP"
STREAM_SHUFFLE = "SHUFFLE"
STREAM_COIN = "COIN"
STREAM_SEARCH = "SEARCH"
STREAM_RANDOM_SELECTION = "RANDOM_SELECTION"
STREAM_AGENT_ENTROPY_PLAYER_0 = "AGENT_ENTROPY_PLAYER_0"
STREAM_AGENT_ENTROPY_PLAYER_1 = "AGENT_ENTROPY_PLAYER_1"
STREAM_DOMAINS = (
    STREAM_SETUP,
    STREAM_SHUFFLE,
    STREAM_COIN,
    STREAM_SEARCH,
    STREAM_RANDOM_SELECTION,
    STREAM_AGENT_ENTROPY_PLAYER_0,
    STREAM_AGENT_ENTROPY_PLAYER_1,
)
ENGINE_STREAM_DOMAINS = (
    STREAM_SETUP,
    STREAM_SHUFFLE,
    STREAM_COIN,
    STREAM_SEARCH,
    STREAM_RANDOM_SELECTION,
)
RESERVED_AGENT_STREAM_DOMAINS = (
    STREAM_AGENT_ENTROPY_PLAYER_0,
    STREAM_AGENT_ENTROPY_PLAYER_1,
)

UINT64_MAX = (1 << 64) - 1
UINT64_SPACE = 1 << 64
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]*$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class RngGatewayError(ValueError):
    """A Package 3 reference-contract input failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> RngGatewayError:
    return RngGatewayError(code, message)


def _digest(domain: bytes, *parts: bytes) -> bytes:
    return sha256(domain + b"".join(parts)).digest()


def _root(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise _fail("RNG_ROOT_INVALID", f"{label} must be a 32-byte digest")
    return value


def _u64(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise _fail("RNG_TYPE_INVALID", f"{label} must be a non-boolean uint64")
    return value


def _u16(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise _fail("RNG_TYPE_INVALID", f"{label} must be a non-boolean uint16")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value or _IDENTIFIER_RE.fullmatch(value) is None:
        raise _fail("RNG_SOURCE_SITE_INVALID", f"{label} must be a canonical identifier")
    return value


def _path(value: Any, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value or value.startswith("/") or "\\" in value:
        raise _fail("RNG_SOURCE_SITE_INVALID", f"{label} must be a canonical relative POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or _PATH_SEGMENT_RE.fullmatch(part) is None for part in parts):
        raise _fail("RNG_SOURCE_SITE_INVALID", f"{label} must be a canonical relative POSIX path")
    return value


def _hex_root(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_HEX_RE.fullmatch(value) is None:
        raise _fail("RNG_COVERAGE_INVALID", f"{label} must be lowercase SHA-256 hex")
    return value


def sequence_root(values: Sequence[bytes]) -> bytes:
    """Return the replay-compatible root of an ordered card-instance sequence."""

    return _digest(b"V631/SEQUENCE", canonical_cbor_encode(list(values)))


def permutation_root(values: Sequence[int]) -> bytes:
    """Return the replay-compatible root of a Fisher-Yates permutation vector."""

    return _digest(b"V631/SHUFFLE/PERMUTATION", canonical_cbor_encode(list(values)))


@dataclass(frozen=True, slots=True)
class SourceSite:
    """A stable source identity rooted to one pinned source tree and location."""

    pinned_source_root: bytes
    canonical_relative_path: str
    site_name: str
    stable_site_id: bytes

    def __post_init__(self) -> None:
        _root(self.pinned_source_root, "pinned_source_root")
        _path(self.canonical_relative_path, "canonical_relative_path")
        _identifier(self.site_name, "site_name")
        _root(self.stable_site_id, "stable_site_id")

    @property
    def source_site_id(self) -> bytes:
        return self.stable_site_id

    @property
    def display_id(self) -> str:
        """Hex display form; canonical trace wire values use ``source_site_id`` bytes."""

        return self.source_site_id.hex()

    def canonical(self) -> dict[str, str]:
        return {
            "source_site_id": self.display_id,
            "canonical_relative_path": self.canonical_relative_path,
            "site_name": self.site_name,
        }


@dataclass(frozen=True, slots=True)
class StreamBinding:
    """A named, domain-separated stream with its deterministic commitment."""

    stream_domain: str
    stream_id: bytes
    stream_seed_commitment: bytes
    generator_algorithm_id: str = RAW_DRAW_ALGORITHM_ID
    counter: int = 0

    def __post_init__(self) -> None:
        if self.stream_domain not in STREAM_DOMAINS:
            raise _fail("RNG_STREAM_DOMAIN_INVALID", "stream_domain is not one of the frozen named domains")
        _root(self.stream_id, "stream_id")
        _root(self.stream_seed_commitment, "stream_seed_commitment")
        if self.generator_algorithm_id != RAW_DRAW_ALGORITHM_ID:
            raise _fail("RNG_ALGORITHM_INVALID", "stream generator algorithm is not frozen")
        _u64(self.counter, "counter")

    def trace_payload(self) -> list[Any]:
        return [self.stream_id, self.stream_seed_commitment, self.generator_algorithm_id, self.counter]


@dataclass(frozen=True, slots=True)
class RawDrawEvidence:
    """One exact replay-compatible raw uint64 draw and its trace sequence."""

    event_sequence: int
    stream_id: bytes
    counter_before: int
    raw_output_bytes: bytes
    counter_after: int
    source_site_id: bytes

    def __post_init__(self) -> None:
        _u64(self.event_sequence, "event_sequence")
        _root(self.stream_id, "stream_id")
        before = _u64(self.counter_before, "counter_before")
        if type(self.raw_output_bytes) is not bytes or len(self.raw_output_bytes) != 8:
            raise _fail("RNG_RAW_DRAW_MISMATCH", "raw uint64 output must be exactly eight bytes")
        if _u64(self.counter_after, "counter_after") != before + 1:
            raise _fail("RNG_COUNTER_GAP", "raw draw counter must advance by exactly one")
        _root(self.source_site_id, "source_site_id")

    @property
    def raw_uint64(self) -> int:
        return int.from_bytes(self.raw_output_bytes, "big")

    def trace_payload(self) -> list[Any]:
        return [
            self.stream_id,
            self.counter_before,
            64,
            self.raw_output_bytes,
            self.counter_after,
            self.source_site_id,
        ]


def _rejection_limit(exclusive_upper_bound: int) -> int:
    upper = _u64(exclusive_upper_bound, "exclusive_upper_bound")
    if upper == 0:
        raise _fail("RNG_BOUNDED_SAMPLE_INVALID", "exclusive_upper_bound must be positive")
    return UINT64_SPACE % upper


@dataclass(frozen=True, slots=True)
class BoundedSampleEvidence:
    """Complete raw-draw accounting for one unbiased bounded sample."""

    stream_id: bytes
    exclusive_upper_bound: int
    draws: tuple[RawDrawEvidence, ...]
    sampling_algorithm_id: str = BOUNDED_SAMPLING_ALGORITHM_ID

    def __post_init__(self) -> None:
        _root(self.stream_id, "stream_id")
        _rejection_limit(self.exclusive_upper_bound)
        if self.sampling_algorithm_id != BOUNDED_SAMPLING_ALGORITHM_ID:
            raise _fail("RNG_ALGORITHM_INVALID", "bounded sampling algorithm is not frozen")
        if type(self.draws) is not tuple or not self.draws:
            raise _fail("RNG_REJECTION_ACCOUNTING_MISMATCH", "bounded sampling requires at least one raw draw")
        previous_after: int | None = None
        for draw in self.draws:
            if type(draw) is not RawDrawEvidence or draw.stream_id != self.stream_id:
                raise _fail("RNG_REJECTION_ACCOUNTING_MISMATCH", "bounded draws must use one rooted stream")
            if previous_after is not None and draw.counter_before != previous_after:
                raise _fail("RNG_COUNTER_GAP", "bounded draw counters are not contiguous")
            previous_after = draw.counter_after
        threshold = _rejection_limit(self.exclusive_upper_bound)
        for draw in self.draws[:-1]:
            if draw.raw_uint64 >= threshold:
                raise _fail("RNG_REJECTION_ACCOUNTING_MISMATCH", "a recorded rejection was in the acceptance interval")
        if self.draws[-1].raw_uint64 < threshold:
            raise _fail("RNG_REJECTION_ACCOUNTING_MISMATCH", "bounded sample lacks an accepted raw draw")

    @property
    def counter_before(self) -> int:
        return self.draws[0].counter_before

    @property
    def counter_after(self) -> int:
        return self.draws[-1].counter_after

    @property
    def rejected_raw_values(self) -> tuple[int, ...]:
        return tuple(draw.raw_uint64 for draw in self.draws[:-1])

    @property
    def accepted_raw_value(self) -> int:
        return self.draws[-1].raw_uint64

    @property
    def mapped_result(self) -> int:
        return self.accepted_raw_value % self.exclusive_upper_bound

    def trace_payload(self) -> list[Any]:
        return [
            self.sampling_algorithm_id,
            self.stream_id,
            self.exclusive_upper_bound,
            _rejection_limit(self.exclusive_upper_bound),
            [draw.event_sequence for draw in self.draws],
            list(self.rejected_raw_values),
            [False] * len(self.rejected_raw_values) + [True],
            self.accepted_raw_value,
            self.mapped_result,
            self.counter_before,
            self.counter_after,
        ]


@dataclass(frozen=True, slots=True)
class ShuffleEvidence:
    """Exact Fisher-Yates permutation evidence compatible with SHUFFLE_APPLIED."""

    shuffle_id: bytes
    zone_id: str
    input_cards: tuple[bytes, ...]
    samples: tuple[BoundedSampleEvidence, ...]
    permutation: tuple[int, ...]
    output_cards: tuple[bytes, ...]
    shuffle_algorithm_id: str = SHUFFLE_ALGORITHM_ID

    def __post_init__(self) -> None:
        _root(self.shuffle_id, "shuffle_id")
        _identifier(self.zone_id, "zone_id")
        if type(self.input_cards) is not tuple:
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle input must be an ordered tuple")
        if any(type(card) is not bytes or len(card) != 32 for card in self.input_cards):
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle input must contain 32-byte card-instance IDs")
        if self.shuffle_algorithm_id != SHUFFLE_ALGORITHM_ID:
            raise _fail("RNG_ALGORITHM_INVALID", "shuffle algorithm is not frozen")
        if type(self.samples) is not tuple or len(self.samples) != max(len(self.input_cards) - 1, 0):
            raise _fail("RNG_SHUFFLE_INVALID", "Fisher-Yates requires one bounded sample for every swap")
        if any(type(sample) is not BoundedSampleEvidence for sample in self.samples):
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle samples are malformed")
        expected_bounds = tuple(range(len(self.input_cards), 1, -1))
        if tuple(sample.exclusive_upper_bound for sample in self.samples) != expected_bounds:
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle sample bounds are not Fisher-Yates bounds")
        all_draws = tuple(draw for sample in self.samples for draw in sample.draws)
        if all_draws and any(left.event_sequence + 1 != right.event_sequence for left, right in zip(all_draws, all_draws[1:])):
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle raw event sequences must form one exact replay range")
        expected = list(range(len(self.input_cards)))
        for index, sample in zip(range(len(expected) - 1, 0, -1), self.samples):
            expected[index], expected[sample.mapped_result] = expected[sample.mapped_result], expected[index]
        if (
            type(self.permutation) is not tuple
            or any(type(index) is not int for index in self.permutation)
            or tuple(expected) != self.permutation
        ):
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle permutation does not match Fisher-Yates evidence")
        if tuple(self.input_cards[index] for index in self.permutation) != self.output_cards:
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle output does not match the exact permutation")

    @property
    def rng_event_range(self) -> list[int]:
        draws = tuple(draw for sample in self.samples for draw in sample.draws)
        if not draws:
            return []
        return [draws[0].event_sequence, draws[-1].event_sequence]

    def trace_payload(self) -> list[Any]:
        inputs, outputs, permutation = list(self.input_cards), list(self.output_cards), list(self.permutation)
        return [
            self.shuffle_id,
            self.zone_id,
            inputs,
            sequence_root(inputs),
            self.shuffle_algorithm_id,
            self.rng_event_range,
            permutation,
            permutation_root(permutation),
            outputs,
            sequence_root(outputs),
        ]


class DeterministicRngGateway:
    """Stateful reference issuer for rooted streams and monotonic raw draws."""

    def __init__(self, seed_material: SeedMaterial, pinned_source_root: bytes, source_sites: Iterable[SourceSite]) -> None:
        if type(seed_material) is not SeedMaterial:
            raise _fail("RNG_SEED_BINDING_MISMATCH", "seed_material must be SeedMaterial")
        self.seed_material = seed_material
        self.pinned_source_root = _root(pinned_source_root, "pinned_source_root")
        sites = tuple(source_sites)
        if not sites or any(type(site) is not SourceSite or site.pinned_source_root != self.pinned_source_root for site in sites):
            raise _fail("RNG_SOURCE_SITE_UNCOVERED", "every RNG source site must bind the pinned source root")
        by_id = {site.source_site_id: site for site in sites}
        if len(by_id) != len(sites):
            raise _fail("RNG_SOURCE_SITE_INVALID", "source-site inventory has duplicate identities")
        self._sites = MappingProxyType(by_id)
        self._streams: dict[str, StreamBinding] = {}
        self._stream_seeds: dict[str, bytes] = {}
        self._draws: dict[int, RawDrawEvidence] = {}

    def bind_stream(self, stream_domain: str) -> StreamBinding:
        if stream_domain not in STREAM_DOMAINS:
            raise _fail("RNG_STREAM_DOMAIN_INVALID", "stream_domain is not one of the frozen named domains")
        if stream_domain in RESERVED_AGENT_STREAM_DOMAINS:
            raise _fail(
                "RNG_AGENT_STREAM_BROKER_REQUIRED",
                "reserved agent entropy streams are inaccessible from the engine reference gateway",
            )
        existing = self._streams.get(stream_domain)
        if existing is not None:
            return existing
        stream_seed = self.seed_material.stream_seed(stream_domain)
        binding = StreamBinding(
            stream_domain,
            self.seed_material.stream_id(stream_domain),
            self.seed_material.stream_seed_commitment(stream_domain),
        )
        self._stream_seeds[stream_domain] = stream_seed
        self._streams[stream_domain] = binding
        return binding

    def stream_payload(self, stream_domain: str) -> list[Any]:
        return self.bind_stream(stream_domain).trace_payload()

    def _site(self, site: SourceSite) -> SourceSite:
        if type(site) is not SourceSite or site.pinned_source_root != self.pinned_source_root or site.source_site_id not in self._sites:
            raise _fail("RNG_SOURCE_SITE_UNCOVERED", "RNG draw originated from an uncovered source site")
        return site

    def draw_raw_uint64(self, stream_domain: str, site: SourceSite, event_sequence: int) -> RawDrawEvidence:
        sequence = _u64(event_sequence, "event_sequence")
        if sequence in self._draws:
            raise _fail("RNG_EVENT_SEQUENCE_REUSED", "raw draw event_sequence is already bound")
        source = self._site(site)
        current = self.bind_stream(stream_domain)
        raw = sha256(
            RAW_DRAW_DOMAIN
            + canonical_cbor_encode([self._stream_seeds[stream_domain], current.counter])
        ).digest()[:8]
        evidence = RawDrawEvidence(sequence, current.stream_id, current.counter, raw, current.counter + 1, source.source_site_id)
        self._draws[sequence] = evidence
        self._streams[stream_domain] = StreamBinding(
            current.stream_domain,
            current.stream_id,
            current.stream_seed_commitment,
            current.generator_algorithm_id,
            evidence.counter_after,
        )
        return evidence

    def verify_raw_draw(self, evidence: RawDrawEvidence) -> None:
        if type(evidence) is not RawDrawEvidence:
            raise _fail("RNG_RAW_DRAW_MISMATCH", "raw draw evidence is malformed")
        if evidence.event_sequence in self._draws:
            raise _fail("RNG_EVENT_SEQUENCE_REUSED", "raw draw event_sequence is already bound")
        matching = [binding for binding in self._streams.values() if binding.stream_id == evidence.stream_id]
        if len(matching) != 1:
            raise _fail("RNG_STREAM_DOMAIN_INVALID", "raw draw references an unbound stream")
        binding = matching[0]
        if evidence.source_site_id not in self._sites:
            raise _fail("RNG_SOURCE_SITE_UNCOVERED", "raw draw references an uncovered source site")
        if evidence.counter_before != binding.counter:
            raise _fail("RNG_COUNTER_GAP", "raw draw counter is skipped, reused, or reordered")
        expected = sha256(
            RAW_DRAW_DOMAIN
            + canonical_cbor_encode([self._stream_seeds[binding.stream_domain], binding.counter])
        ).digest()[:8]
        if evidence.raw_output_bytes != expected:
            raise _fail("RNG_RAW_DRAW_MISMATCH", "raw draw does not match the pinned deterministic stream")
        self._draws[evidence.event_sequence] = evidence
        self._streams[binding.stream_domain] = StreamBinding(
            binding.stream_domain,
            binding.stream_id,
            binding.stream_seed_commitment,
            binding.generator_algorithm_id,
            evidence.counter_after,
        )

    def bounded_sample_from_draws(self, exclusive_upper_bound: int, draws: Iterable[RawDrawEvidence]) -> BoundedSampleEvidence:
        issued = tuple(draws)
        if not issued:
            raise _fail("RNG_REJECTION_ACCOUNTING_MISMATCH", "bounded sampling requires raw draw evidence")
        for draw in issued:
            if self._draws.get(draw.event_sequence) != draw:
                raise _fail("RNG_REJECTION_ACCOUNTING_MISMATCH", "bounded sample must reference exact issued raw draws")
        return BoundedSampleEvidence(issued[0].stream_id, exclusive_upper_bound, issued)

    def shuffle(
        self,
        shuffle_id: bytes,
        zone_id: str,
        input_cards: Iterable[bytes],
        site: SourceSite,
        raw_event_sequences: Sequence[Sequence[int]],
    ) -> ShuffleEvidence:
        cards = tuple(input_cards)
        if len(raw_event_sequences) != max(len(cards) - 1, 0):
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle requires one raw-event sequence group per Fisher-Yates swap")
        samples: list[BoundedSampleEvidence] = []
        for upper, sequences in zip(range(len(cards), 1, -1), raw_event_sequences):
            draws = tuple(self.draw_raw_uint64(STREAM_SHUFFLE, site, sequence) for sequence in sequences)
            samples.append(self.bounded_sample_from_draws(upper, draws))
        permutation = list(range(len(cards)))
        for index, sample in zip(range(len(cards) - 1, 0, -1), samples):
            permutation[index], permutation[sample.mapped_result] = permutation[sample.mapped_result], permutation[index]
        result = tuple(cards[index] for index in permutation)
        return ShuffleEvidence(shuffle_id, zone_id, cards, tuple(samples), tuple(permutation), result)

    def zero_authority_report(self) -> Mapping[str, Any]:
        return freeze(
            zero_authority(
                "OFFLINE_RNG_REFERENCE_CONTRACT",
                detail="Deterministic RNG evidence is local conformance only; no engine execution or source-completeness claim exists.",
                extra={
                    "authority": False,
                    "upload_authorized": False,
                    "ast_completeness_claimed": False,
                    "ir_completeness_claimed": False,
                    "uncovered_entropy_absence_proven": False,
                },
            )
        )


def validate_trace_rng_payload(
    event_type: int,
    payload: Any,
    *,
    draws_by_sequence: Mapping[int, RawDrawEvidence] | None = None,
    source_site_ids: Iterable[bytes] = (),
) -> None:
    """Validate the fixed payload arrays consumed by ``canonical_trace_replay``.

    The function deliberately accepts the replayer's event taxonomy but is
    stricter for Package 3: raw draws are always exactly uint64 and bounded
    rejection decisions are checked against the exact uint64 threshold.
    """

    if type(event_type) is not int:
        raise _fail("RNG_TRACE_PAYLOAD_INVALID", "event_type must be a non-boolean trace code")
    known_sites = set(source_site_ids)
    if event_type == RNG_STREAM_BOUND:
        if type(payload) is not list or len(payload) != 4:
            raise _fail("RNG_TRACE_PAYLOAD_INVALID", "RNG_STREAM_BOUND payload is malformed")
        StreamBinding("SETUP", payload[0], payload[1], payload[2], payload[3])
        return
    if event_type == RNG_DRAW:
        if type(payload) is not list or len(payload) != 6:
            raise _fail("RNG_TRACE_PAYLOAD_INVALID", "RNG_DRAW payload is malformed")
        evidence = RawDrawEvidence(0, payload[0], payload[1], payload[3], payload[4], payload[5])
        if payload[2] != 64 or (known_sites and evidence.source_site_id not in known_sites):
            raise _fail("RNG_TRACE_PAYLOAD_INVALID", "RNG_DRAW is not a covered raw uint64 draw")
        return
    if event_type == RNG_BOUNDED_SAMPLE:
        if type(payload) is not list or len(payload) != 11 or draws_by_sequence is None:
            raise _fail("RNG_TRACE_PAYLOAD_INVALID", "RNG_BOUNDED_SAMPLE requires raw draw evidence")
        algorithm, stream, upper, threshold, sequences, rejected, acceptance, accepted, mapped, before, after = payload
        if (
            algorithm != BOUNDED_SAMPLING_ALGORITHM_ID
            or threshold != _rejection_limit(upper)
            or type(sequences) is not list
            or type(acceptance) is not list
        ):
            raise _fail("RNG_TRACE_PAYLOAD_INVALID", "bounded sample algorithm or sequence list is invalid")
        draws = tuple(draws_by_sequence.get(_u64(sequence, "raw draw event sequence")) for sequence in sequences)
        if not draws or any(draw is None for draw in draws):
            raise _fail("RNG_REJECTION_ACCOUNTING_MISMATCH", "bounded sample references unknown raw evidence")
        evidence = BoundedSampleEvidence(stream, upper, tuple(draw for draw in draws if draw is not None))
        if (
            rejected != list(evidence.rejected_raw_values)
            or acceptance != [False] * len(evidence.rejected_raw_values) + [True]
            or accepted != evidence.accepted_raw_value
            or mapped != evidence.mapped_result
            or before != evidence.counter_before
            or after != evidence.counter_after
        ):
            raise _fail("RNG_REJECTION_ACCOUNTING_MISMATCH", "bounded sample payload omits or alters rejection evidence")
        return
    if event_type == SHUFFLE_APPLIED:
        if type(payload) is not list or len(payload) != 10:
            raise _fail("RNG_TRACE_PAYLOAD_INVALID", "SHUFFLE_APPLIED payload is malformed")
        _shuffle, zone, inputs, input_root, algorithm, rng_range, permutation, perm_root, outputs, output_root = payload
        _identifier(zone, "zone_id")
        if algorithm != SHUFFLE_ALGORITHM_ID or type(inputs) is not list or type(outputs) is not list or type(permutation) is not list:
            raise _fail("RNG_TRACE_PAYLOAD_INVALID", "shuffle algorithm or arrays are invalid")
        if any(type(card) is not bytes or len(card) != 32 for card in inputs + outputs) or input_root != sequence_root(inputs) or output_root != sequence_root(outputs):
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle sequence roots are invalid")
        if (
            any(type(index) is not int for index in permutation)
            or sorted(permutation) != list(range(len(inputs)))
            or perm_root != permutation_root(permutation)
            or outputs != [inputs[index] for index in permutation]
        ):
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle permutation or output is invalid")
        if type(rng_range) is not list or (
            rng_range
            and (
                len(rng_range) != 2
                or any(type(value) is not int for value in rng_range)
                or rng_range[0] > rng_range[1]
            )
        ):
            raise _fail("RNG_SHUFFLE_INVALID", "shuffle RNG event range is invalid")
        return
    raise _fail("RNG_TRACE_PAYLOAD_INVALID", "event_type is not a Package 3 RNG event")


def build_rng_coverage_manifest(pinned_source_root: bytes, source_sites: Iterable[SourceSite]) -> Mapping[str, Any]:
    """Build a rooted inventory without asserting AST/IR completeness."""

    root = _root(pinned_source_root, "pinned_source_root")
    sites = tuple(source_sites)
    if not sites or any(type(site) is not SourceSite or site.pinned_source_root != root for site in sites):
        raise _fail("RNG_COVERAGE_INVALID", "coverage sites must all bind the pinned source root")
    canonical_sites = [site.canonical() for site in sites]
    if canonical_sites != sorted(canonical_sites, key=lambda item: (item["canonical_relative_path"], item["site_name"])):
        raise _fail("RNG_COVERAGE_INVALID", "coverage sites must use canonical path/site order")
    if len({item["source_site_id"] for item in canonical_sites}) != len(canonical_sites):
        raise _fail("RNG_COVERAGE_INVALID", "coverage sites contain duplicate stable IDs")
    payload: dict[str, Any] = {
        "schema": RNG_COVERAGE_SCHEMA,
        "mode": RNG_COVERAGE_MODE,
        "pinned_source_root_sha256": root.hex(),
        "source_sites": canonical_sites,
        "ast_completeness_claimed": False,
        "ir_completeness_claimed": False,
        "uncovered_entropy_absence_proven": False,
        "authority": False,
        "upload_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "sealed_holdout_access_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
    }
    payload["coverage_manifest_root_sha256"] = canonical_sha256(payload)
    return MappingProxyType(payload)


def validate_rng_coverage_manifest(value: Any, *, expected_source_root: bytes | None = None) -> Mapping[str, Any]:
    """Fail closed on any completeness or authority claim in a coverage inventory."""

    if not isinstance(value, Mapping):
        raise _fail("RNG_COVERAGE_INVALID", "coverage manifest must be a mapping")
    required = {
        "schema", "mode", "pinned_source_root_sha256", "source_sites", "ast_completeness_claimed",
        "ir_completeness_claimed", "uncovered_entropy_absence_proven", "authority", "upload_authorized",
        "calibration_upload_authorized", "production_upload_authorized", "sealed_holdout_access_authorized",
        "agent_modification_authorized", "permits", "coverage_manifest_root_sha256",
    }
    if set(value) != required or value["schema"] != RNG_COVERAGE_SCHEMA or value["mode"] != RNG_COVERAGE_MODE:
        raise _fail("RNG_COVERAGE_INVALID", "coverage manifest schema or fields are invalid")
    root_hex = _hex_root(value["pinned_source_root_sha256"], "pinned_source_root_sha256")
    if expected_source_root is not None and root_hex != _root(expected_source_root, "expected_source_root").hex():
        raise _fail("RNG_COVERAGE_INVALID", "coverage manifest is bound to another source root")
    if any(value[key] is not False for key in ("ast_completeness_claimed", "ir_completeness_claimed", "uncovered_entropy_absence_proven", "authority", "upload_authorized", "calibration_upload_authorized", "production_upload_authorized", "sealed_holdout_access_authorized", "agent_modification_authorized")) or value["permits"] != []:
        raise _fail("RNG_COVERAGE_AUTHORITY_CLAIM", "offline RNG coverage cannot claim completeness or authority")
    sites = value["source_sites"]
    if type(sites) is not list or not sites:
        raise _fail("RNG_COVERAGE_INVALID", "coverage manifest must inventory source sites")
    root = bytes.fromhex(root_hex)
    reconstructed: list[dict[str, str]] = []
    for item in sites:
        if type(item) is not dict or set(item) != {"source_site_id", "canonical_relative_path", "site_name"}:
            raise _fail("RNG_COVERAGE_INVALID", "coverage source-site record is invalid")
        stable_id = _hex_root(item["source_site_id"], "source_site_id")
        site = SourceSite(root, item["canonical_relative_path"], item["site_name"], bytes.fromhex(stable_id))
        if item["source_site_id"] != site.display_id:
            raise _fail("RNG_COVERAGE_INVALID", "coverage source-site ID is stale")
        reconstructed.append(site.canonical())
    if reconstructed != sorted(reconstructed, key=lambda item: (item["canonical_relative_path"], item["site_name"])) or len({item["source_site_id"] for item in reconstructed}) != len(reconstructed):
        raise _fail("RNG_COVERAGE_INVALID", "coverage source-site inventory is noncanonical")
    payload = {key: value[key] for key in value if key != "coverage_manifest_root_sha256"}
    if value["coverage_manifest_root_sha256"] != canonical_sha256(payload):
        raise _fail("RNG_COVERAGE_INVALID", "coverage manifest root is stale")
    return freeze(dict(value))


__all__ = [
    "BOUNDED_SAMPLING_ALGORITHM_ID", "BoundedSampleEvidence", "DeterministicRngGateway", "RAW_DRAW_ALGORITHM_ID",
    "RNG_BOUNDED_SAMPLE", "RNG_COVERAGE_MODE", "RNG_COVERAGE_SCHEMA", "RNG_DRAW", "RNG_GATEWAY_SCHEMA",
    "ENGINE_STREAM_DOMAINS", "RESERVED_AGENT_STREAM_DOMAINS", "RNG_STREAM_BOUND", "RngGatewayError", "SHUFFLE_ALGORITHM_ID", "SHUFFLE_APPLIED", "STREAM_AGENT_ENTROPY_PLAYER_0",
    "STREAM_AGENT_ENTROPY_PLAYER_1", "STREAM_COIN", "STREAM_DOMAINS", "STREAM_RANDOM_SELECTION", "STREAM_SEARCH",
    "STREAM_SETUP", "STREAM_SHUFFLE", "RawDrawEvidence", "SeedMaterial", "ShuffleEvidence", "SourceSite", "StreamBinding",
    "UINT64_MAX", "build_rng_coverage_manifest", "permutation_root", "sequence_root", "validate_rng_coverage_manifest",
    "validate_trace_rng_payload",
]
