from __future__ import annotations

import random
import unicodedata

import pytest

from evaluation_v6_3_1.m0_inventory import (
    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
    M0_TEMPLATE_EMISSION_STATUS_UNPROVEN,
    BlockerRecord,
    CompleteCensus,
    ConstructKey,
    Disposition,
    DomainCode,
    InventoryCandidate,
    M0InventoryError,
    SourceAnchor,
    SubjectKey,
    TemplateEmissionProof,
    canonical_first_blocker,
)


def _expect(code: str, call, *args) -> None:
    with pytest.raises(M0InventoryError) as raised:
        call(*args)
    assert raised.value.code == code


def _anchor(offset: int) -> SourceAnchor:
    return SourceAnchor("/v631302/src/Export.cpp", offset, offset + 1)


def _construct(offset: int = 10, *, path: tuple[int, ...] = (0,)) -> ConstructKey:
    return ConstructKey(path, "CallExpr", _anchor(offset))


def _subject(domain: DomainCode, value: int = 0) -> SubjectKey:
    if domain is DomainCode.SOURCE_DEFINITION_INVENTORY:
        return SubjectKey(domain, ((value,), "FunctionDecl", tuple(_anchor(value + 1).as_array())))
    if domain is DomainCode.TU_RUNTIME_INVENTORY:
        return SubjectKey(
            domain,
            (
                "VarDecl",
                "g",
                "int",
                1,
                (value,),
                "/v631302/src/Export.cpp",
                value,
                value + 1,
                (value,),
            ),
        )
    return SubjectKey(
        domain,
        (
            "FunctionDecl",
            f"definition_{value}",
            "void ()",
            1,
            (value,),
            "/v631302/src/Export.cpp",
            value,
            value + 1,
        ),
    )


def _candidate(
    candidate_id: str,
    domain: DomainCode = DomainCode.DEFINITION_INVOCATION_INVENTORY,
    value: int = 0,
    *,
    disposition: Disposition = Disposition.UNSUPPORTED,
    failure_code: str | None = "M0_UNKNOWN",
    proof: TemplateEmissionProof | None = None,
) -> InventoryCandidate:
    return InventoryCandidate(
        candidate_id,
        domain,
        _subject(domain, value),
        _construct(value + 100, path=(value,)),
        disposition,
        failure_code,
        proof,
    )


def test_permuted_visitor_and_container_order_choose_identical_blocker() -> None:
    rows = [
        _candidate("third", DomainCode.DEFINITION_INVOCATION_INVENTORY, 3),
        _candidate("first", DomainCode.SOURCE_DEFINITION_INVENTORY, 1),
        _candidate("second", DomainCode.TU_RUNTIME_INVENTORY, 2),
    ]
    expected = canonical_first_blocker(CompleteCensus.declare_complete([row.candidate_id for row in rows], rows))
    assert expected is not None
    for seed in range(20):
        shuffled = rows.copy()
        random.Random(seed).shuffle(shuffled)
        result = canonical_first_blocker(
            CompleteCensus.declare_complete([row.candidate_id for row in reversed(shuffled)], shuffled)
        )
        assert result == expected
        assert result.ordering_bytes == expected.ordering_bytes


def test_duplicate_and_omitted_candidates_fail_closed() -> None:
    row = _candidate("one")
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        CompleteCensus.declare_complete,
        ["one", "one"],
        [row],
    )
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        CompleteCensus.declare_complete,
        ["one", "two"],
        [row, _candidate("two", value=0)],
    )
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        CompleteCensus.declare_complete,
        ["one", "missing"],
        [row],
    )


def test_pointer_like_data_and_noncanonical_paths_are_rejected() -> None:
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SubjectKey,
        DomainCode.DEFINITION_INVOCATION_INVENTORY,
        ((object(),),),
    )
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, SourceAnchor, "/tmp/not-source.cc", 0, 1)
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SourceAnchor,
        "/v631302/src/../other.cc",
        0,
        1,
    )
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SourceAnchor,
        "/v631302/src/Export.cpp",
        True,
        1,
    )
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SubjectKey,
        True,
        ((), "FunctionDecl", tuple(_anchor(1).as_array())),
    )
    decomposed = unicodedata.normalize("NFD", "definition_é")
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        InventoryCandidate,
        decomposed,
        DomainCode.DEFINITION_INVOCATION_INVENTORY,
        _subject(DomainCode.DEFINITION_INVOCATION_INVENTORY),
        _construct(),
        Disposition.UNSUPPORTED,
        "M0_UNKNOWN",
    )


def test_domain_precedence_is_part_of_the_complete_cbor_key() -> None:
    source = _candidate("source", DomainCode.SOURCE_DEFINITION_INVENTORY, 100)
    runtime = _candidate("runtime", DomainCode.TU_RUNTIME_INVENTORY, 0)
    census = CompleteCensus.declare_complete(["runtime", "source"], [runtime, source])
    assert canonical_first_blocker(census) == BlockerRecord.from_candidate(source)


def test_numeric_canonical_cbor_order_is_not_python_tuple_order() -> None:
    # The short inner array starts with 0x81 and therefore sorts before 0x82,
    # even though Python tuple order would place (0, 115) before (9,).
    short = _candidate("short", value=0)
    long_subject = SubjectKey(
        DomainCode.DEFINITION_INVOCATION_INVENTORY,
        ("FunctionDecl", "a", "void ()", 1, (0, 115), "/v631302/src/Export.cpp", 0, 1),
    )
    long = InventoryCandidate(
        "long",
        DomainCode.DEFINITION_INVOCATION_INVENTORY,
        long_subject,
        _construct(101, path=(1,)),
        Disposition.UNSUPPORTED,
        "M0_UNKNOWN",
    )
    # Replace the short key with (9,) to make the difference visible.
    short = InventoryCandidate(
        "short",
        DomainCode.DEFINITION_INVOCATION_INVENTORY,
        SubjectKey(
            DomainCode.DEFINITION_INVOCATION_INVENTORY,
            ("FunctionDecl", "a", "void ()", 1, (9,), "/v631302/src/Export.cpp", 0, 1),
        ),
        _construct(100, path=(0,)),
        Disposition.UNSUPPORTED,
        "M0_UNKNOWN",
    )
    census = CompleteCensus.declare_complete(["long", "short"], [long, short])
    assert canonical_first_blocker(census) == BlockerRecord.from_candidate(short)


def test_definition_subject_key_is_exactly_the_binding3_key() -> None:
    valid = _subject(DomainCode.DEFINITION_INVOCATION_INVENTORY, 7)
    assert valid.value[0] == "FunctionDecl"
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SubjectKey,
        DomainCode.DEFINITION_INVOCATION_INVENTORY,
        ("FunctionDecl", "too_short"),
    )
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SubjectKey,
        DomainCode.DEFINITION_INVOCATION_INVENTORY,
        ("BlockDecl", "x", "void ()", 1, (), "/v631302/src/Export.cpp", 0, 1),
    )
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SubjectKey,
        DomainCode.DEFINITION_INVOCATION_INVENTORY,
        ("FunctionDecl", "x", "void ()", 3, (), "/v631302/src/Export.cpp", 0, 1),
    )
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SubjectKey,
        DomainCode.DEFINITION_INVOCATION_INVENTORY,
        ("FunctionDecl", "x", "void ()", 1, (116,), "/v631302/src/Export.cpp", 0, 1),
    )
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SubjectKey,
        DomainCode.SOURCE_DEFINITION_INVENTORY,
        ((), "BlockDecl", tuple(_anchor(1).as_array())),
    )
    invalid_global = list(_subject(DomainCode.TU_RUNTIME_INVENTORY).value)
    invalid_global[0] = "DecompositionDecl"
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        SubjectKey,
        DomainCode.TU_RUNTIME_INVENTORY,
        tuple(invalid_global),
    )


def test_selection_requires_a_declared_complete_census() -> None:
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, canonical_first_blocker, [])
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        CompleteCensus.declare_complete,
        ["one"],
        [],
    )


def test_template_exclusion_requires_all_five_proofs() -> None:
    _expect(
        M0_TEMPLATE_EMISSION_STATUS_UNPROVEN,
        TemplateEmissionProof,
        True,
        True,
        True,
        False,
        True,
    )
    _expect(
        M0_TEMPLATE_EMISSION_STATUS_UNPROVEN,
        lambda: _candidate(
            "discarded",
            DomainCode.DEFINITION_INVOCATION_INVENTORY,
            9,
            disposition=Disposition.NONINSTANTIATED_OR_DISCARDED,
            failure_code=None,
        ),
    )
    proof = TemplateEmissionProof(True, True, True, True, True)
    candidate = _candidate(
        "discarded",
        domain=DomainCode.SOURCE_DEFINITION_INVENTORY,
        value=9,
        disposition=Disposition.NONINSTANTIATED_OR_DISCARDED,
        failure_code=None,
        proof=proof,
    )
    assert canonical_first_blocker(CompleteCensus.declare_complete(["discarded"], [candidate])) is None
    _expect(
        M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
        lambda: _candidate(
            "wrong_domain",
            value=10,
            disposition=Disposition.NONINSTANTIATED_OR_DISCARDED,
            failure_code=None,
            proof=proof,
        ),
    )


def test_first_blocker_is_deterministic_after_complete_census_validation() -> None:
    rows = [_candidate("z", value=9), _candidate("a", value=1)]
    census = CompleteCensus.declare_complete(["a", "z"], rows)
    first = canonical_first_blocker(census)
    assert first == BlockerRecord.from_candidate(rows[1])
    assert first is not None
    assert first.ordering_bytes == min(blocker.ordering_bytes for blocker in census.blockers())
