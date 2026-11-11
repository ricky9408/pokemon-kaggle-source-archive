"""Offline, zero-authority implementation of V631-RNG-3A/1.

Only the frozen A1-A3, A15, B1/B5, and C1-C4 contracts live here.  The
module deliberately has no campaign, permit, upload, holdout, or engine
authority and does not depend on an older RNG or trace representation.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
from types import MappingProxyType
from typing import Any, Final, Mapping


PROTOCOL_ID: Final = "V631-RNG-3A/1"
PROTOCOL_VERSION: Final = 631302
RETIRED_PROTOCOL_VERSION: Final = 631301
BASE_BINDING_SPEC_SHA256: Final = "eba5425b1c7632c50750f6946dca02ed672a350cbdf467650fad7c2083298400"
EVENT_AMENDMENT_SPEC_SHA256: Final = "4078872a2c7d0156d7cb9c1b43eb56135b1c584616c3c35fc911c75f21ddcfea"
BINDING_SPEC_SHA256: Final = EVENT_AMENDMENT_SPEC_SHA256
AUTHORITY: Final = "NO_UPLOAD"
ZERO_ID: Final = bytes(32)
UINT64_MAX: Final = (1 << 64) - 1

DS_SHARE_COMMIT: Final = b"V631/P3A/SHARE-COMMIT\x00"
DS_SECRET: Final = b"V631/P3A/SECRET\x00"
DS_SCHEDULE: Final = b"V631/P3A/SCHEDULE\x00"
DS_MATCH: Final = b"V631/P3A/MATCH\x00"
DS_SEED_RECORD: Final = b"V631/P3A/SEED-RECORD\x00"
DS_RUN_BIND: Final = b"V631/P3A/RUN-BIND\x00"
DS_STREAM_KEY: Final = b"V631/P3A/STREAM-KEY\x00"
DS_STREAM_ID: Final = b"V631/P3A/STREAM-ID\x00"
DS_RAW: Final = b"V631/P3A/RAW\x00"
DS_BRANCH_ID: Final = b"V631/P3A/BRANCH-ID\x00"
DS_BRANCH_KEY: Final = b"V631/P3A/BRANCH-KEY\x00"
DS_EVENT_302: Final = b"V631/P3A/EVENT/631302\x00"
DS_BRANCH_LEAF: Final = b"V631/P3A/BRANCH-LEAF\x00"
DS_BRANCH_GENESIS: Final = b"V631/P3A/BRANCH-GENESIS\x00"
DS_BRANCH_STEP: Final = b"V631/P3A/BRANCH-STEP\x00"
DS_BRANCH_FINAL: Final = b"V631/P3A/BRANCH-FINAL\x00"
DS_RESUME_SESSION: Final = b"V631/P3A/RESUME-SESSION\x00"
DS_RESUME_CAP: Final = b"V631/P3A/RESUME-CAPABILITY\x00"
DS_RESUME_COMMIT: Final = b"V631/P3A/RESUME-COMMITMENT\x00"
DS_RESUME_PROOF: Final = b"V631/P3A/RESUME-PROOF\x00"
DS_STATE: Final = b"V631/P3A/STATE\x00"
DS_REVEAL: Final = b"V631/P3A/REVEAL\x00"

_ASCII_LABEL_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:-")
_MAX_DEPTH = 64


class UnifiedRngProtocolError(ValueError):
    """A V631-RNG-3A/1 value failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CanonicalCborTruncated(UnifiedRngProtocolError):
    """Internal/profile signal that a deterministic CBOR value is incomplete."""


def _fail(code: str, message: str) -> UnifiedRngProtocolError:
    return UnifiedRngProtocolError(code, message)


def _uint(value: Any, label: str, maximum: int = UINT64_MAX) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", f"{label} must be an unsigned integer")
    return value


def _bstr(value: Any, label: str, length: int = 32) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", f"{label} must be a {length}-byte bstr")
    return value


def ascii_label(value: Any, label: str = "label") -> bytes:
    """Validate the protocol's byte-only ASCII label profile."""
    if type(value) is not bytes or not 1 <= len(value) <= 64:
        raise _fail("RNG_TEXT_OR_NFC_POLICY_VIOLATION", f"{label} must be a 1..64 byte label")
    if any(byte not in _ASCII_LABEL_BYTES for byte in value):
        raise _fail("RNG_TEXT_OR_NFC_POLICY_VIOLATION", f"{label} contains a forbidden byte")
    return value


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value <= UINT64_MAX:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "CBOR argument exceeds uint64")


def canonical_cbor_encode(value: Any, *, _depth: int = 0) -> bytes:
    """Encode only definite-length arrays, uints, and byte strings.

    This is intentionally narrower than a general RFC 8949 implementation:
    maps, tags, floats, text, booleans, null, negative integers, and tuples
    are outside this normative profile.
    """
    if _depth > _MAX_DEPTH:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "CBOR nesting exceeds the profile")
    if type(value) is bytes:
        return _head(2, len(value)) + value
    if type(value) is int:
        if value < 0:
            raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "negative integers are forbidden")
        return _head(0, value)
    if type(value) is list:
        encoded = [canonical_cbor_encode(item, _depth=_depth + 1) for item in value]
        return _head(4, len(encoded)) + b"".join(encoded)
    raise _fail("RNG_TEXT_OR_NFC_POLICY_VIOLATION", f"unsupported normative type: {type(value).__name__}")


class _CborDecoder:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0

    def take(self, count: int) -> bytes:
        end = self.offset + count
        if count < 0 or end > len(self.raw):
            raise CanonicalCborTruncated(
                "RNG_CANONICAL_CBOR_MISMATCH",
                "truncated CBOR",
            )
        result = self.raw[self.offset:end]
        self.offset = end
        return result

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "indefinite or unsupported CBOR argument")
        value = int.from_bytes(self.take(width), "big")
        minimum = {1: 24, 2: 256, 4: 65536, 8: 1 << 32}[width]
        if value < minimum:
            raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "non-minimal CBOR argument")
        return value

    def value(self, depth: int = 0) -> Any:
        if depth > _MAX_DEPTH:
            raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "CBOR nesting exceeds the profile")
        initial = self.take(1)[0]
        major, additional = initial >> 5, initial & 0x1F
        if major == 0:
            return self.argument(additional)
        if major == 2:
            return self.take(self.argument(additional))
        if major == 4:
            return [self.value(depth + 1) for _ in range(self.argument(additional))]
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "maps, tags, floats, text, and negative values are forbidden")


def canonical_cbor_decode(raw: bytes) -> list[Any]:
    """Decode one complete normative array and reject noncanonical bytes."""
    if type(raw) is not bytes or not raw:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "CBOR input must be non-empty bytes")
    decoder = _CborDecoder(raw)
    value = decoder.value()
    if decoder.offset != len(raw) or type(value) is not list:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "normative CBOR must be one complete array")
    if canonical_cbor_encode(value) != raw:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "CBOR is not deterministic")
    return value


def canonical_cbor_decode_prefix(raw: bytes, offset: int = 0) -> tuple[list[Any], int]:
    """Decode one deterministic array at ``offset`` and return its end offset.

    The 631302 trace is a literal concatenation of canonical arrays without
    framing bytes.  This narrow prefix API exposes exactly the boundary needed
    to walk that stream while retaining the same deterministic-CBOR checks as
    :func:`canonical_cbor_decode`.
    """

    if type(raw) is not bytes or not raw:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "CBOR input must be non-empty bytes")
    if type(offset) is not int or not 0 <= offset < len(raw):
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "CBOR offset is outside the input")
    decoder = _CborDecoder(raw)
    decoder.offset = offset
    value = decoder.value()
    end = decoder.offset
    if type(value) is not list:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "normative CBOR value must be an array")
    if canonical_cbor_encode(value) != raw[offset:end]:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "CBOR is not deterministic")
    return value, end


def _hash(domain: bytes, value: bytes) -> bytes:
    return sha256(domain + value).digest()


def _record(raw_or_value: bytes | list[Any], length: int, label: str) -> list[Any]:
    value = canonical_cbor_decode(raw_or_value) if type(raw_or_value) is bytes else raw_or_value
    if type(value) is not list or len(value) != length:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", f"{label} must have {length} array fields")
    return value


def _require_current_version(value: Any, label: str) -> None:
    if value == RETIRED_PROTOCOL_VERSION:
        raise _fail("RNG_PROTOCOL_631301_RETIRED", f"{label} uses retired protocol 631301")
    if value != PROTOCOL_VERSION:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", f"{label} uses an unsupported protocol version")


@dataclass(frozen=True, slots=True)
class SeedCommitment:
    campaign_root: bytes
    model_root: bytes
    local_engine_root: bytes
    panel_schedule_root: bytes
    share_commitment_a: bytes
    share_commitment_b: bytes
    share_nonce_a: bytes
    share_nonce_b: bytes

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            _bstr(getattr(self, name), name)

    def as_array(self) -> list[Any]:
        return [
            PROTOCOL_VERSION, 1, self.campaign_root, self.model_root,
            self.local_engine_root, self.panel_schedule_root,
            self.share_commitment_a, self.share_commitment_b,
            self.share_nonce_a, self.share_nonce_b,
        ]

    def to_bytes(self) -> bytes:
        return canonical_cbor_encode(self.as_array())


def derive_share_commitment(
    campaign_root: bytes,
    panel_schedule_root: bytes,
    share_nonce: bytes,
    share: bytes,
) -> bytes:
    return _hash(DS_SHARE_COMMIT, _bstr(campaign_root, "campaign_root") + _bstr(panel_schedule_root, "panel_schedule_root") + _bstr(share_nonce, "share_nonce") + _bstr(share, "share"))


share_commitment = derive_share_commitment


def build_seed_commitment(
    campaign_root: bytes,
    model_root: bytes,
    local_engine_root: bytes,
    panel_schedule_root: bytes,
    share_commitment_a: bytes,
    share_commitment_b: bytes,
    share_nonce_a: bytes,
    share_nonce_b: bytes,
) -> SeedCommitment:
    return SeedCommitment(campaign_root, model_root, local_engine_root, panel_schedule_root, share_commitment_a, share_commitment_b, share_nonce_a, share_nonce_b)


make_seed_commitment = build_seed_commitment


def decode_seed_commitment(raw: bytes | list[Any]) -> SeedCommitment:
    value = _record(raw, 10, "seed commitment")
    _require_current_version(value[0], "seed commitment")
    if value[1] != 1:
        raise _fail("RNG_CANONICAL_CBOR_MISMATCH", "wrong seed commitment version or type")
    return SeedCommitment(*(_bstr(item, f"seed commitment field {index}") for index, item in enumerate(value[2:], 2)))


def seed_commitment_root(commitment: SeedCommitment | bytes | list[Any]) -> bytes:
    record = commitment if isinstance(commitment, SeedCommitment) else decode_seed_commitment(commitment)
    return _hash(DS_SEED_RECORD, record.to_bytes())


def verify_share_openings(commitment: SeedCommitment | bytes | list[Any], share_a: bytes, share_b: bytes) -> bytes:
    record = commitment if isinstance(commitment, SeedCommitment) else decode_seed_commitment(commitment)
    share_a = _bstr(share_a, "share_A")
    share_b = _bstr(share_b, "share_B")
    expected_a = derive_share_commitment(record.campaign_root, record.panel_schedule_root, record.share_nonce_a, share_a)
    expected_b = derive_share_commitment(record.campaign_root, record.panel_schedule_root, record.share_nonce_b, share_b)
    if not hmac.compare_digest(expected_a, record.share_commitment_a) or not hmac.compare_digest(expected_b, record.share_commitment_b):
        raise _fail("RNG_SECRET_COMMITMENT_MISMATCH", "revealed share does not open its commitment")
    return derive_evaluator_secret(seed_commitment_root(record), share_a, share_b)


def derive_evaluator_secret(seed_commitment_root_value: bytes, share_a: bytes, share_b: bytes) -> bytes:
    return _hash(DS_SECRET, _bstr(seed_commitment_root_value, "seed_commitment_root") + _bstr(share_a, "share_A") + _bstr(share_b, "share_B"))


@dataclass(frozen=True, slots=True)
class RunBinding:
    seed_commitment_root: bytes
    panel_schedule_root: bytes
    match_id: bytes
    common_seed_id: int
    candidate_archive_sha256: bytes
    control_archive_sha256: bytes
    candidate_seat: int
    engine_binary_sha256: bytes
    ruleset_sha256: bytes
    card_catalog_sha256: bytes
    candidate_deck_root: bytes
    control_deck_root: bytes
    run_manifest_root: bytes

    def __post_init__(self) -> None:
        for name in ("seed_commitment_root", "panel_schedule_root", "match_id", "candidate_archive_sha256", "control_archive_sha256", "engine_binary_sha256", "ruleset_sha256", "card_catalog_sha256", "candidate_deck_root", "control_deck_root", "run_manifest_root"):
            _bstr(getattr(self, name), name)
        _uint(self.common_seed_id, "common_seed_id", 0xFFFFFFFF)
        _uint(self.candidate_seat, "candidate_seat", 1)
        expected_match_id = derive_match_id(
            self.panel_schedule_root,
            self.common_seed_id,
            self.candidate_archive_sha256,
            self.control_archive_sha256,
            self.candidate_seat,
        )
        if not hmac.compare_digest(self.match_id, expected_match_id):
            raise _fail("RNG_RUN_BINDING_MISMATCH", "match_id does not match the run binding")

    def as_array(self) -> list[Any]:
        return [PROTOCOL_VERSION, 2, self.seed_commitment_root, self.panel_schedule_root, self.match_id, self.common_seed_id, self.candidate_archive_sha256, self.control_archive_sha256, self.candidate_seat, self.engine_binary_sha256, self.ruleset_sha256, self.card_catalog_sha256, self.candidate_deck_root, self.control_deck_root, self.run_manifest_root]

    def to_bytes(self) -> bytes:
        return canonical_cbor_encode(self.as_array())


def derive_match_id(panel_schedule_root: bytes, common_seed_id: int, candidate_archive_sha256: bytes, control_archive_sha256: bytes, candidate_seat: int) -> bytes:
    return _hash(DS_MATCH, _bstr(panel_schedule_root, "panel_schedule_root") + _uint(common_seed_id, "common_seed_id", 0xFFFFFFFF).to_bytes(4, "big") + _bstr(candidate_archive_sha256, "candidate_archive_sha256") + _bstr(control_archive_sha256, "control_archive_sha256") + bytes([_uint(candidate_seat, "candidate_seat", 1)]))


def build_run_binding(seed_commitment_root_value: bytes, panel_schedule_root: bytes, common_seed_id: int, candidate_archive_sha256: bytes, control_archive_sha256: bytes, candidate_seat: int, engine_binary_sha256: bytes, ruleset_sha256: bytes, card_catalog_sha256: bytes, candidate_deck_root: bytes, control_deck_root: bytes, run_manifest_root: bytes) -> RunBinding:
    return RunBinding(seed_commitment_root_value, panel_schedule_root, derive_match_id(panel_schedule_root, common_seed_id, candidate_archive_sha256, control_archive_sha256, candidate_seat), common_seed_id, candidate_archive_sha256, control_archive_sha256, candidate_seat, engine_binary_sha256, ruleset_sha256, card_catalog_sha256, candidate_deck_root, control_deck_root, run_manifest_root)


def decode_run_binding(raw: bytes | list[Any]) -> RunBinding:
    value = _record(raw, 15, "run binding")
    _require_current_version(value[0], "run binding")
    if value[1] != 2:
        raise _fail("RNG_RUN_BINDING_MISMATCH", "wrong run binding version or type")
    fields = [_bstr(item, f"run binding field {index}") if index not in (5, 8) else item for index, item in enumerate(value[2:], 2)]
    return RunBinding(*fields)


def run_binding_root(binding: RunBinding | bytes | list[Any]) -> bytes:
    record = binding if isinstance(binding, RunBinding) else decode_run_binding(binding)
    return _hash(DS_RUN_BIND, record.to_bytes())


def verify_run_binding(
    binding: RunBinding | bytes | list[Any],
    commitment: SeedCommitment | bytes | list[Any],
) -> bytes:
    record = binding if isinstance(binding, RunBinding) else decode_run_binding(binding)
    commitment_record = (
        commitment
        if isinstance(commitment, SeedCommitment)
        else decode_seed_commitment(commitment)
    )
    if not hmac.compare_digest(
        record.seed_commitment_root,
        seed_commitment_root(commitment_record),
    ):
        raise _fail("RNG_RUN_BINDING_MISMATCH", "run binding references a different seed commitment")
    if not hmac.compare_digest(
        record.panel_schedule_root,
        commitment_record.panel_schedule_root,
    ):
        raise _fail("RNG_RUN_BINDING_MISMATCH", "run binding references a different panel schedule")
    return run_binding_root(record)


@dataclass(frozen=True, slots=True)
class SeedReveal:
    seed_commitment_root: bytes
    panel_execution_close_root: bytes
    share_a: bytes
    share_b: bytes
    reveal_manifest_root: bytes

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            _bstr(getattr(self, name), name)

    def as_array(self) -> list[Any]:
        return [PROTOCOL_VERSION, 13, self.seed_commitment_root, self.panel_execution_close_root, self.share_a, self.share_b, self.reveal_manifest_root]

    def to_bytes(self) -> bytes:
        return canonical_cbor_encode(self.as_array())


def build_seed_reveal(seed_commitment_root_value: bytes, panel_execution_close_root: bytes, share_a: bytes, share_b: bytes, reveal_manifest_root: bytes) -> SeedReveal:
    return SeedReveal(seed_commitment_root_value, panel_execution_close_root, share_a, share_b, reveal_manifest_root)


def decode_seed_reveal(raw: bytes | list[Any]) -> SeedReveal:
    value = _record(raw, 7, "seed reveal")
    _require_current_version(value[0], "seed reveal")
    if value[1] != 13:
        raise _fail("RNG_SECRET_COMMITMENT_MISMATCH", "wrong reveal version or type")
    return SeedReveal(*(_bstr(item, f"seed reveal field {index}") for index, item in enumerate(value[2:], 2)))


def seed_reveal_root(reveal: SeedReveal | bytes | list[Any]) -> bytes:
    record = reveal if isinstance(reveal, SeedReveal) else decode_seed_reveal(reveal)
    return _hash(DS_REVEAL, record.to_bytes())


def verify_seed_reveal(
    reveal: SeedReveal | bytes | list[Any],
    commitment: SeedCommitment | bytes | list[Any],
    *,
    expected_panel_execution_close_root: bytes,
    expected_reveal_manifest_root: bytes,
) -> bytes:
    record = reveal if isinstance(reveal, SeedReveal) else decode_seed_reveal(reveal)
    commitment_record = commitment if isinstance(commitment, SeedCommitment) else decode_seed_commitment(commitment)
    expected_root = seed_commitment_root(commitment_record)
    if not hmac.compare_digest(record.seed_commitment_root, expected_root):
        raise _fail("RNG_SECRET_COMMITMENT_MISMATCH", "reveal references a different seed commitment")
    if not hmac.compare_digest(
        record.panel_execution_close_root,
        _bstr(expected_panel_execution_close_root, "expected_panel_execution_close_root"),
    ):
        raise _fail("RNG_SECRET_COMMITMENT_MISMATCH", "reveal references a different panel close")
    if not hmac.compare_digest(
        record.reveal_manifest_root,
        _bstr(expected_reveal_manifest_root, "expected_reveal_manifest_root"),
    ):
        raise _fail("RNG_SECRET_COMMITMENT_MISMATCH", "reveal references a different manifest")
    return verify_share_openings(commitment_record, record.share_a, record.share_b)


def derive_schedule_seed(evaluator_secret: bytes, panel_schedule_root: bytes, common_seed_id: int) -> bytes:
    secret = _bstr(evaluator_secret, "evaluator_secret")
    root = _bstr(panel_schedule_root, "panel_schedule_root")
    seed = _uint(common_seed_id, "common_seed_id", 0xFFFFFFFF)
    return hmac.new(secret, DS_SCHEDULE + root + seed.to_bytes(4, "big"), "sha256").digest()


def derive_stream_key(schedule_seed: bytes, site_id: bytes, object_instance_id: bytes, purpose_code: int, stream_ordinal: int) -> bytes:
    seed = _bstr(schedule_seed, "schedule_seed")
    site = _bstr(site_id, "site_id")
    object_id = _bstr(object_instance_id, "object_instance_id")
    purpose = _uint(purpose_code, "purpose_code", 0xFFFF)
    ordinal = _uint(stream_ordinal, "stream_ordinal", 0xFFFFFFFF)
    return hmac.new(seed, DS_STREAM_KEY + site + object_id + purpose.to_bytes(2, "big") + ordinal.to_bytes(4, "big"), "sha256").digest()


def derive_stream_id(session_id: bytes, site_id: bytes, object_instance_id: bytes, purpose_code: int, stream_ordinal: int) -> bytes:
    session = _bstr(session_id, "session_id")
    site = _bstr(site_id, "site_id")
    object_id = _bstr(object_instance_id, "object_instance_id")
    purpose = _uint(purpose_code, "purpose_code", 0xFFFF)
    ordinal = _uint(stream_ordinal, "stream_ordinal", 0xFFFFFFFF)
    return _hash(DS_STREAM_ID, session + canonical_cbor_encode([site, object_id, purpose, ordinal]))


semantic_stream_id = derive_stream_id


def derive_branch_key(stream_key: bytes, branch_id: bytes) -> bytes:
    return hmac.new(_bstr(stream_key, "stream_key"), DS_BRANCH_KEY + _bstr(branch_id, "branch_id"), "sha256").digest()


def derive_raw_value(stream_key: bytes, raw_counter: int, branch_id: bytes = ZERO_ID) -> int:
    key = _bstr(stream_key, "stream_key")
    counter = _uint(raw_counter, "raw_counter")
    branch = _bstr(branch_id, "branch_id")
    if branch != ZERO_ID:
        key = derive_branch_key(key, branch)
    digest = hmac.new(key, DS_RAW + counter.to_bytes(8, "big"), "sha256").digest()
    return int.from_bytes(digest[:8], "big")


def derive_authoritative_raw_value(stream_key: bytes, raw_counter: int) -> int:
    return derive_raw_value(stream_key, raw_counter, ZERO_ID)


def derive_branch_raw_value(stream_key: bytes, branch_id: bytes, raw_counter: int) -> int:
    branch = _bstr(branch_id, "branch_id")
    if branch == ZERO_ID:
        raise _fail("RNG_CRN_KDF_CONTEXT_INVALID", "branch raw values require a nonzero branch_id")
    return derive_raw_value(stream_key, raw_counter, branch)


def verify_raw_value(expected: int, stream_key: bytes, raw_counter: int, branch_id: bytes = ZERO_ID) -> bool:
    if type(expected) is not int or expected != derive_raw_value(stream_key, raw_counter, branch_id):
        raise _fail("RNG_CRN_KDF_CONTEXT_INVALID", "raw value does not reproduce from the revealed secret")
    return True


@dataclass(frozen=True, slots=True)
class PublicReport:
    """Immutable local evidence; it can never authorize campaign actions."""

    state: str = "OFFLINE_CONFORMANCE_ONLY"
    detail: str = ""
    authority: str = AUTHORITY
    calibration_upload_authorized: bool = False
    production_upload_authorized: bool = False
    sealed_holdout_access_authorized: bool = False
    agent_modification_authorized: bool = False
    permits: tuple[Any, ...] = ()
    early_disclosure_absence_proven: bool = False
    physical_inaccessibility_proven: bool = False
    auditor_noncollusion_proven: bool = False
    publication_timing_authenticated: bool = False

    def __post_init__(self) -> None:
        if self.authority != AUTHORITY or any((self.calibration_upload_authorized, self.production_upload_authorized, self.sealed_holdout_access_authorized, self.agent_modification_authorized, self.early_disclosure_absence_proven, self.physical_inaccessibility_proven, self.auditor_noncollusion_proven, self.publication_timing_authenticated)) or self.permits != ():
            raise _fail("RNG_PROTOCOL_AMBIGUOUS", "public reports are permanently zero-authority")

    def as_dict(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "state": self.state,
            "detail": self.detail,
            "authority": AUTHORITY,
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "sealed_holdout_access_authorized": False,
            "agent_modification_authorized": False,
            "permits": (),
            "early_disclosure_absence_proven": False,
            "physical_inaccessibility_proven": False,
            "auditor_noncollusion_proven": False,
            "publication_timing_authenticated": False,
        })


def zero_authority_report(state: str = "OFFLINE_CONFORMANCE_ONLY", detail: str = "") -> PublicReport:
    if type(state) is not str or type(detail) is not str:
        raise _fail("RNG_PROTOCOL_AMBIGUOUS", "report metadata must be text outside the normative protocol")
    return PublicReport(state=state, detail=detail)


make_public_report = zero_authority_report


__all__ = [
    "AUTHORITY", "BASE_BINDING_SPEC_SHA256", "BINDING_SPEC_SHA256",
    "EVENT_AMENDMENT_SPEC_SHA256", "PROTOCOL_ID", "PROTOCOL_VERSION",
    "RETIRED_PROTOCOL_VERSION", "UINT64_MAX", "ZERO_ID",
    "DS_SHARE_COMMIT", "DS_SECRET", "DS_SCHEDULE", "DS_MATCH",
    "DS_SEED_RECORD", "DS_RUN_BIND", "DS_STREAM_KEY", "DS_STREAM_ID",
    "DS_RAW", "DS_BRANCH_ID", "DS_BRANCH_KEY", "DS_EVENT_302",
    "DS_BRANCH_LEAF", "DS_BRANCH_GENESIS", "DS_BRANCH_STEP", "DS_BRANCH_FINAL",
    "DS_RESUME_SESSION", "DS_RESUME_CAP", "DS_RESUME_COMMIT", "DS_RESUME_PROOF",
    "DS_STATE", "DS_REVEAL",
    "CanonicalCborTruncated", "UnifiedRngProtocolError", "SeedCommitment", "RunBinding", "SeedReveal", "PublicReport",
    "ascii_label", "canonical_cbor_encode", "canonical_cbor_decode", "canonical_cbor_decode_prefix",
    "derive_share_commitment", "share_commitment", "build_seed_commitment", "make_seed_commitment",
    "decode_seed_commitment", "seed_commitment_root", "verify_share_openings", "derive_evaluator_secret",
    "derive_match_id", "build_run_binding", "decode_run_binding", "run_binding_root", "verify_run_binding",
    "build_seed_reveal", "decode_seed_reveal", "seed_reveal_root", "verify_seed_reveal",
    "derive_schedule_seed", "derive_stream_key", "derive_stream_id", "semantic_stream_id",
    "derive_branch_key", "derive_raw_value", "derive_authoritative_raw_value", "derive_branch_raw_value", "verify_raw_value",
    "zero_authority_report", "make_public_report",
]
