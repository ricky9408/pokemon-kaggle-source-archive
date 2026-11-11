"""Zero-authority canonical inventory primitives for protocol 631302 M0.

This module implements only Binding 9's deterministic candidate accounting and
diagnostic ordering.  It neither observes Clang nor grants any campaign,
engine, upload, holdout, or agent-modification authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Any, Iterable
import unicodedata

from .canonical_trace_codec import canonical_cbor_encode


M0_DIAGNOSTIC_INVENTORY_INCOMPLETE = "M0_DIAGNOSTIC_INVENTORY_INCOMPLETE"
M0_TEMPLATE_EMISSION_STATUS_UNPROVEN = "M0_TEMPLATE_EMISSION_STATUS_UNPROVEN"

SOURCE_ROOT = "/v631302/src"
CALLABLE_DECLARATION_KINDS = frozenset(
    {
        "FunctionDecl",
        "CXXMethodDecl",
        "CXXConstructorDecl",
        "CXXDestructorDecl",
        "CXXConversionDecl",
    }
)


class M0InventoryError(ValueError):
    """A Binding-9 inventory value failed closed with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> M0InventoryError:
    return M0InventoryError(code, message)


class DomainCode(IntEnum):
    """The stage-ordered inventories frozen by Binding 9."""

    SOURCE_DEFINITION_INVENTORY = 1
    TU_RUNTIME_INVENTORY = 2
    DEFINITION_INVOCATION_INVENTORY = 3


class Disposition(StrEnum):
    """The only admissible candidate dispositions."""

    REPRESENTED = "REPRESENTED"
    NONINSTANTIATED_OR_DISCARDED = "NONINSTANTIATED_OR_DISCARDED"
    UNSUPPORTED = "UNSUPPORTED"


def _uint(value: Any, bits: int, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 1 << bits:
        raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, f"{label} must fit uint{bits}")
    return value


def _domain_code(value: Any, label: str) -> DomainCode:
    if type(value) is DomainCode:
        return value
    if type(value) is not int:
        raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, f"{label} is invalid")
    try:
        return DomainCode(value)
    except ValueError as exc:
        raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, f"{label} is invalid") from exc


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise _fail(
            M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
            f"{label} must be nonempty NUL-free text",
        )
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, f"{label} is not valid UTF-8") from exc
    if unicodedata.normalize("NFC", value) != value:
        raise _fail(
            M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
            f"{label} is not NFC-normalized",
        )
    return value


def _source_path(value: Any, label: str) -> str:
    path = _text(value, label)
    if not path.startswith(SOURCE_ROOT + "/") or path.endswith("/"):
        raise _fail(
            M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
            f"{label} must be a canonical path below {SOURCE_ROOT}",
        )
    components = path.split("/")[1:]
    if any(component in ("", ".", "..") for component in components):
        raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, f"{label} has a noncanonical component")
    return path


def _array(value: Any, label: str) -> tuple[Any, ...]:
    if type(value) not in (list, tuple):
        raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, f"{label} must be an array")
    return tuple(value)


def _wire(value: Any) -> list[Any]:
    if type(value) is tuple:
        return [_wire(item) for item in value]
    return value


def _ast_path(value: Any, label: str) -> tuple[int, ...]:
    return tuple(_uint(item, 32, f"{label} component") for item in _array(value, label))


@dataclass(frozen=True)
class SourceAnchor:
    """A contiguous source span below the pinned source mount."""

    normalized_source_path: str
    begin_byte_offset: int
    end_byte_offset: int

    def __post_init__(self) -> None:
        path = _source_path(self.normalized_source_path, "normalized_source_path")
        begin = _uint(self.begin_byte_offset, 64, "begin_byte_offset")
        end = _uint(self.end_byte_offset, 64, "end_byte_offset")
        if end <= begin:
            raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, "source anchor span must be nonempty")
        object.__setattr__(self, "normalized_source_path", path)
        object.__setattr__(self, "begin_byte_offset", begin)
        object.__setattr__(self, "end_byte_offset", end)

    @classmethod
    def from_array(cls, value: Any) -> "SourceAnchor":
        row = _array(value, "source_anchor")
        if len(row) != 3:
            raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, "source_anchor has the wrong width")
        return cls(row[0], row[1], row[2])

    def as_array(self) -> list[Any]:
        return [self.normalized_source_path, self.begin_byte_offset, self.end_byte_offset]


@dataclass(frozen=True)
class SubjectKey:
    """A validated domain-specific subject key from Binding 9."""

    domain_code: DomainCode
    value: tuple[Any, ...]

    def __post_init__(self) -> None:
        domain = _domain_code(self.domain_code, "subject domain code")
        raw = _array(self.value, "subject_key")
        if domain is DomainCode.SOURCE_DEFINITION_INVENTORY:
            if len(raw) != 3:
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "source-definition subject key has the wrong width",
                )
            declaration_kind = _text(raw[1], "source-definition ast_decl_kind")
            if declaration_kind not in CALLABLE_DECLARATION_KINDS:
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "source-definition ast_decl_kind is outside the Binding-3 set",
                )
            normalized: tuple[Any, ...] = (
                _ast_path(raw[0], "source-definition anchor_ast_path"),
                declaration_kind,
                tuple(SourceAnchor.from_array(raw[2]).as_array()),
            )
        elif domain is DomainCode.TU_RUNTIME_INVENTORY:
            if len(raw) != 9:
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "TU-runtime subject key has the wrong width",
                )
            targets = tuple(_uint(item, 32, "TU-runtime target index") for item in _array(raw[4], "target_indices"))
            if targets != tuple(sorted(set(targets))):
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "TU-runtime target indices must be strictly increasing",
                )
            normalized = (
                _text(raw[0], "TU-runtime ast_decl_kind"),
                _text(raw[1], "TU-runtime qualified_name"),
                _text(raw[2], "TU-runtime raw_qual_type"),
                _uint(raw[3], 8, "TU-runtime linkage_code"),
                targets,
                _source_path(raw[5], "TU-runtime normalized_source_path"),
                _uint(raw[6], 64, "TU-runtime begin_byte_offset"),
                _uint(raw[7], 64, "TU-runtime end_byte_offset"),
                _ast_path(raw[8], "TU-runtime anchor_ast_path"),
            )
            if normalized[0] != "VarDecl":
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "TU-runtime ast_decl_kind must be VarDecl",
                )
            if normalized[3] not in (1, 2):
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "TU-runtime linkage_code is outside the Binding-3 table",
                )
            if any(target > 115 for target in targets):
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "TU-runtime target index is outside 0..115",
                )
            if normalized[7] <= normalized[6]:
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "TU-runtime source span must be nonempty",
                )
        else:
            if len(raw) != 8:
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "definition-invocation subject key has the wrong width",
                )
            declaration_kind = _text(raw[0], "definition ast_decl_kind")
            if declaration_kind not in CALLABLE_DECLARATION_KINDS:
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "definition ast_decl_kind is outside the Binding-3 set",
                )
            targets = tuple(
                _uint(item, 32, "definition target index")
                for item in _array(raw[4], "definition target_indices")
            )
            if targets != tuple(sorted(set(targets))) or any(target > 115 for target in targets):
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "definition target indices must be strictly increasing values in 0..115",
                )
            normalized = (
                declaration_kind,
                _text(raw[1], "definition qualified_name"),
                _text(raw[2], "definition raw_qual_type"),
                _uint(raw[3], 8, "definition linkage_code"),
                targets,
                _source_path(raw[5], "definition virtual path"),
                _uint(raw[6], 64, "definition begin offset"),
                _uint(raw[7], 64, "definition end offset"),
            )
            if normalized[3] not in (1, 2):
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "definition linkage_code is outside the Binding-3 table",
                )
            if normalized[7] <= normalized[6]:
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "definition source span must be nonempty",
                )
        object.__setattr__(self, "domain_code", domain)
        object.__setattr__(self, "value", normalized)

    def as_array(self) -> list[Any]:
        return _wire(self.value)


@dataclass(frozen=True)
class ConstructKey:
    """A source-anchored construct occurrence key from Binding 9."""

    occurrence_ast_path: tuple[int, ...]
    ast_node_kind: str
    source_anchor: SourceAnchor

    def __post_init__(self) -> None:
        object.__setattr__(self, "occurrence_ast_path", _ast_path(self.occurrence_ast_path, "occurrence_ast_path"))
        object.__setattr__(self, "ast_node_kind", _text(self.ast_node_kind, "ast_node_kind"))
        if type(self.source_anchor) is not SourceAnchor:
            raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, "source_anchor must be a SourceAnchor")

    @classmethod
    def from_array(cls, value: Any) -> "ConstructKey":
        row = _array(value, "construct_key")
        if len(row) != 3:
            raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, "construct_key has the wrong width")
        return cls(_ast_path(row[0], "occurrence_ast_path"), row[1], SourceAnchor.from_array(row[2]))

    def as_array(self) -> list[Any]:
        return [_wire(self.occurrence_ast_path), self.ast_node_kind, self.source_anchor.as_array()]


@dataclass(frozen=True)
class TemplateEmissionProof:
    """The five exact facts required before a template-pattern exclusion."""

    body_remains_dependent: bool
    no_concrete_specialization_definition: bool
    no_emitted_concrete_definition: bool
    every_concrete_specialization_inventoried: bool
    no_runtime_root_resolves_to_template_pattern: bool

    def __post_init__(self) -> None:
        values = (
            self.body_remains_dependent,
            self.no_concrete_specialization_definition,
            self.no_emitted_concrete_definition,
            self.every_concrete_specialization_inventoried,
            self.no_runtime_root_resolves_to_template_pattern,
        )
        if any(type(value) is not bool for value in values) or not all(values):
            raise _fail(
                M0_TEMPLATE_EMISSION_STATUS_UNPROVEN,
                "all five template-emission facts must be proved",
            )


@dataclass(frozen=True)
class InventoryCandidate:
    """One exactly disposed candidate in a Binding-9 complete census."""

    candidate_id: str
    domain_code: DomainCode
    subject_key: SubjectKey
    construct_key: ConstructKey
    disposition: Disposition
    failure_code: str | None = None
    template_emission_proof: TemplateEmissionProof | None = None

    def __post_init__(self) -> None:
        candidate_id = _text(self.candidate_id, "candidate_id")
        try:
            disposition = Disposition(self.disposition)
        except (TypeError, ValueError) as exc:
            raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, "candidate disposition is invalid") from exc
        domain = _domain_code(self.domain_code, "candidate domain code")
        if type(self.subject_key) is not SubjectKey or self.subject_key.domain_code is not domain:
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "candidate subject key does not match its domain",
            )
        if type(self.construct_key) is not ConstructKey:
            raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, "candidate construct key is invalid")
        if disposition is Disposition.UNSUPPORTED:
            if self.failure_code is None:
                raise _fail(
                    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                    "unsupported candidate is missing failure_code",
                )
            failure_code = _text(self.failure_code, "failure_code")
        elif self.failure_code is not None:
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "represented/discarded candidate cannot carry failure_code",
            )
        else:
            failure_code = None
        proof = self.template_emission_proof
        if proof is not None and type(proof) is not TemplateEmissionProof:
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "template_emission_proof is invalid",
            )
        if disposition is Disposition.NONINSTANTIATED_OR_DISCARDED and proof is None:
            raise _fail(
                M0_TEMPLATE_EMISSION_STATUS_UNPROVEN,
                "discarded candidate lacks the exact template-emission proof",
            )
        if (
            disposition is Disposition.NONINSTANTIATED_OR_DISCARDED
            and domain is not DomainCode.SOURCE_DEFINITION_INVENTORY
        ):
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "template-pattern exclusion is valid only in the source-definition inventory",
            )
        if disposition is not Disposition.NONINSTANTIATED_OR_DISCARDED and proof is not None:
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "template-emission proof has the wrong disposition",
            )
        object.__setattr__(self, "candidate_id", candidate_id)
        object.__setattr__(self, "domain_code", domain)
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(self, "failure_code", failure_code)

    @property
    def identity_bytes(self) -> bytes:
        return canonical_cbor_encode(
            [int(self.domain_code), self.subject_key.as_array(), self.construct_key.as_array()]
        )

    def as_array(self) -> list[Any]:
        return [
            self.candidate_id,
            int(self.domain_code),
            self.subject_key.as_array(),
            self.construct_key.as_array(),
            self.disposition.value,
            self.failure_code if self.failure_code is not None else "",
        ]


@dataclass(frozen=True)
class BlockerRecord:
    """A canonical unsupported construct row, derived only from a candidate."""

    domain_code: DomainCode
    subject_key: SubjectKey
    construct_key: ConstructKey
    failure_code: str

    def __post_init__(self) -> None:
        domain = _domain_code(self.domain_code, "blocker domain code")
        if type(self.subject_key) is not SubjectKey or self.subject_key.domain_code is not domain:
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "blocker subject key does not match its domain",
            )
        if type(self.construct_key) is not ConstructKey:
            raise _fail(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, "blocker construct key is invalid")
        object.__setattr__(self, "domain_code", domain)
        object.__setattr__(self, "failure_code", _text(self.failure_code, "failure_code"))

    @classmethod
    def from_candidate(cls, candidate: InventoryCandidate) -> "BlockerRecord":
        if type(candidate) is not InventoryCandidate or candidate.disposition is not Disposition.UNSUPPORTED:
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "only unsupported candidates can become blockers",
            )
        assert candidate.failure_code is not None
        return cls(candidate.domain_code, candidate.subject_key, candidate.construct_key, candidate.failure_code)

    def ordering_array(self) -> list[Any]:
        return [
            int(self.domain_code),
            self.subject_key.as_array(),
            self.construct_key.as_array(),
            self.failure_code,
        ]

    @property
    def ordering_bytes(self) -> bytes:
        return canonical_cbor_encode(self.ordering_array())


@dataclass(frozen=True)
class CompleteCensus:
    """A declared candidate-ID universe with an exact, duplicate-free partition."""

    declared_candidate_ids: tuple[str, ...]
    candidates: tuple[InventoryCandidate, ...]

    def __post_init__(self) -> None:
        declared = tuple(_text(value, "declared candidate_id") for value in _array(self.declared_candidate_ids, "declared_candidate_ids"))
        records = _array(self.candidates, "candidates")
        if any(type(value) is not InventoryCandidate for value in records):
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "candidates must contain InventoryCandidate records",
            )
        if len(declared) != len(set(declared)):
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "declared candidate ID is duplicated",
            )
        ids = tuple(candidate.candidate_id for candidate in records)
        if len(ids) != len(set(ids)):
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "candidate record ID is duplicated",
            )
        identities = tuple(candidate.identity_bytes for candidate in records)
        if len(identities) != len(set(identities)):
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "candidate subject/construct identity is duplicated",
            )
        if set(declared) != set(ids):
            raise _fail(
                M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
                "declared candidate IDs and exactly disposed candidate IDs differ",
            )
        object.__setattr__(self, "declared_candidate_ids", declared)
        object.__setattr__(self, "candidates", records)

    @classmethod
    def declare_complete(
        cls,
        candidate_ids: Iterable[str],
        candidates: Iterable[InventoryCandidate],
    ) -> "CompleteCensus":
        return cls(tuple(candidate_ids), tuple(candidates))

    def blockers(self) -> tuple[BlockerRecord, ...]:
        return tuple(
            BlockerRecord.from_candidate(candidate)
            for candidate in self.candidates
            if candidate.disposition is Disposition.UNSUPPORTED
        )


def canonical_first_blocker(census: CompleteCensus) -> BlockerRecord | None:
    """Return the complete-census minimum blocker by canonical-CBOR bytes."""

    if type(census) is not CompleteCensus:
        raise _fail(
            M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
            "canonical blocker selection requires a declared complete census",
        )
    blockers = census.blockers()
    return min(blockers, key=lambda blocker: blocker.ordering_bytes) if blockers else None


__all__ = [
    "BlockerRecord",
    "CompleteCensus",
    "ConstructKey",
    "Disposition",
    "DomainCode",
    "InventoryCandidate",
    "M0_DIAGNOSTIC_INVENTORY_INCOMPLETE",
    "M0_TEMPLATE_EMISSION_STATUS_UNPROVEN",
    "M0InventoryError",
    "SOURCE_ROOT",
    "SourceAnchor",
    "SubjectKey",
    "TemplateEmissionProof",
    "canonical_first_blocker",
]
