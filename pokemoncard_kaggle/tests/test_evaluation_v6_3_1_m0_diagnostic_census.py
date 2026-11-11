from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import random
import subprocess
import sys

import pytest

from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_encode
import evaluation_v6_3_1.m0_diagnostic_census as census_module
from evaluation_v6_3_1.m0_diagnostic_census import (
    CANONICALIZER_BUNDLE_DOMAIN,
    CANONICALIZER_ENTRY_MODULE_PATH,
    CANONICALIZER_WORKER_ENTRY_PATH,
    DIAGNOSTIC_TARGET_REGISTRY_DOMAIN,
    M0DiagnosticCensusError,
    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
    M0_TEMPLATE_EMISSION_STATUS_UNPROVEN,
    canonicalize_diagnostic_census,
    canonicalize_diagnostic_census_v1,
    canonicalize_native_diagnostic_transport,
    decode_diagnostic_census,
    encode_diagnostic_census,
    validate_diagnostic_census,
)


ROOT = Path(__file__).resolve().parents[1]
ZERO = bytes(32)
ONE = bytes([1]) * 32
PINNED_INTERPRETER_SHA256 = bytes.fromhex(
    "6d972cf21be56fe3c947ab6ba257ff8d08c342dd2714442986791bd9a6dfabfe"
)


def _bundle() -> tuple[list[object], bytes, list[object]]:
    paths = [
        "evaluation_v6_3_1/__init__.py",
        CANONICALIZER_ENTRY_MODULE_PATH,
        "evaluation_v6_3_1/m0_diagnostic_primitives.py",
        CANONICALIZER_WORKER_ENTRY_PATH,
    ]
    files = []
    for relative in sorted(paths, key=lambda value: value.encode("utf-8")):
        raw = (ROOT / relative).read_bytes()
        files.append([relative, len(raw), sha256(raw).digest()])
    manifest: list[object] = [1, CANONICALIZER_ENTRY_MODULE_PATH, files]
    root = sha256(
        canonical_cbor_encode(
            [CANONICALIZER_BUNDLE_DOMAIN, 631302, 1, 1, manifest]
        )
    ).digest()
    worker_sha = next(
        row[2] for row in files if row[0] == CANONICALIZER_WORKER_ENTRY_PATH
    )
    execution_profile: list[object] = [
        1,
        [
            1,
            1,
            51053296,
            "cpython-311",
            "",
            6834488,
            PINNED_INTERPRETER_SHA256,
        ],
        CANONICALIZER_WORKER_ENTRY_PATH,
        worker_sha,
        1,
        1,
        1,
        1,
    ]
    return manifest, root, execution_profile


CANONICALIZER_BUNDLE_MANIFEST, CANONICALIZER_BUNDLE_ROOT, EXECUTION_PROFILE = _bundle()


def _frozen_descriptors() -> list[list[object]]:
    artifact = json.loads(
        (
            ROOT
            / "strategy/evaluation_v6_3_1_entropy_static_closure_sourcebound_20260721.json"
        ).read_text(encoding="utf-8")
    )
    targets = artifact["details"]["compiler_derived_dispatch_proof"]["targets"]
    return [[row["index"], row["name"], row["qual_type"]] for row in targets]


TARGET_DESCRIPTORS = _frozen_descriptors()
REGISTRY_ROOT = sha256(
    canonical_cbor_encode(
        [
            DIAGNOSTIC_TARGET_REGISTRY_DOMAIN,
            631302,
            1,
            0,
            116,
            TARGET_DESCRIPTORS,
        ]
    )
).digest()


def _definition(
    offset: int,
    targets: list[int] | None = None,
    *,
    name: str | None = None,
    raw_type: str | None = None,
) -> list[object]:
    target_indices = [] if targets is None else targets
    if target_indices:
        descriptor = TARGET_DESCRIPTORS[target_indices[0]]
        name = descriptor[1] if name is None else name
        raw_type = descriptor[2] if raw_type is None else raw_type
    return [
        "FunctionDecl",
        f"ns::f{offset}" if name is None else name,
        "void ()" if raw_type is None else raw_type,
        1,
        target_indices,
        "/v631302/src/Export.cpp",
        offset,
        offset + 1,
    ]


def _source_subject(path: tuple[int, ...], offset: int) -> list[object]:
    return [[2, list(path)], "FunctionDecl", ["/v631302/src/Export.cpp", offset, offset + 1]]


def _instance(source_subject: list[object], definition: list[object]) -> list[object]:
    return [2, deepcopy(source_subject), definition]


def _construct(offset: int, kind: str = "CallExpr") -> list[object]:
    return [[offset], kind, ["/v631302/src/Export.cpp", offset + 10, offset + 11]]


def _global(
    offset: int = 2,
    targets: list[int] | None = None,
    *,
    kind: str = "VarDecl",
) -> list[object]:
    return [
        kind,
        f"g{offset}",
        "int",
        1,
        [0] if targets is None else targets,
        "/v631302/src/Export.cpp",
        offset,
        offset + 1,
        [2, [1, offset]],
    ]


def _contains_wire(value: object, target: object) -> bool:
    if value == target:
        return True
    if isinstance(value, list):
        return any(_contains_wire(item, target) for item in value)
    return False


def _base(*, unsupported_source: bool = False) -> list[object]:
    source_subject = _source_subject((0,), 1)
    source_blockers = [[_construct(100), "M0_UNSUPPORTED_CALL"]] if unsupported_source else []
    source = [
        [
            source_subject,
            [0, 0, 0, 0, 0, []],
            3 if unsupported_source else 1,
            source_blockers,
        ]
    ]
    runtime = [[_global(), 4, [1, 1, []], [1, 1, []]]]
    invocation = (
        []
        if unsupported_source
        else [[_instance(source_subject, _definition(1, [0])), []]]
    )
    summary = [
        [1, 0 if unsupported_source else 1, 0, 1 if unsupported_source else 0],
        [1, 1, 0, 0],
        [0, 0, 0, 0],
        1 if unsupported_source else 0,
    ]
    blockers = (
        [[1, source_subject, source_blockers[0][0], source_blockers[0][1]]]
        if unsupported_source
        else []
    )
    return [
        631302,
        1,
        [
            ZERO,
            "collector-v1",
            ONE,
            16,
            1,
            deepcopy(EXECUTION_PROFILE),
            CANONICALIZER_BUNDLE_ROOT,
            deepcopy(CANONICALIZER_BUNDLE_MANIFEST),
        ],
        [0, deepcopy(TARGET_DESCRIPTORS), REGISTRY_ROOT],
        summary,
        source,
        runtime,
        invocation,
        blockers,
    ]


def _two_instance_value(*, occurrences: bool = False) -> list[object]:
    value = _base()
    first_instance = value[7][0][0]
    second_subject = _source_subject((9,), 1)
    second_instance = _instance(second_subject, deepcopy(first_instance[2]))
    value[5].append(
        [second_subject, [0, 0, 0, 0, 1, []], 1, []]
    )
    value[7].append([second_instance, []])
    value[4][0] = [2, 2, 0, 0]
    if occurrences:
        value[7][0][1] = [[_construct(10), 1, []]]
        value[7][1][1] = [[_construct(20), 1, []]]
        value[4][2] = [2, 2, 0, 0]
    return value


def _discarded_source_value() -> list[object]:
    pattern = _source_subject((9,), 10)
    specialization = _source_subject((10,), 20)
    value = _base()
    value[5] = [
        [
            pattern,
            [0, 0, 0, 1, 0, [1, 1, [], [1, [specialization]], []]],
            2,
            [],
        ],
        [specialization, [0, 0, 0, 0, 1, []], 1, []],
    ]
    value[7] = [[_instance(specialization, _definition(20, [0])), []]]
    value[4][0] = [2, 1, 1, 0]
    return value


def _expect(code: str, value: object, *, final: bool = False) -> None:
    with pytest.raises(M0DiagnosticCensusError) as raised:
        (validate_diagnostic_census if final else canonicalize_diagnostic_census)(value)
    assert raised.value.code == code


def test_valid_arrays_only_census_is_canonical_and_byte_stable() -> None:
    value = _base()
    canonical = canonicalize_diagnostic_census(value)
    assert canonical == value
    assert validate_diagnostic_census(canonical) == canonical
    encoded = encode_diagnostic_census(value)
    assert encoded == canonical_cbor_encode(canonical)
    assert decode_diagnostic_census(encoded) == canonical
    assert b"candidate_id" not in encoded


def test_internal_native_transport_is_consumed_once_and_canonicalized() -> None:
    value = _base()
    raw = canonical_cbor_encode(
        [value[3][1], value[4][:3], value[5], value[6], value[7]]
    )
    canonical = canonicalize_native_diagnostic_transport(
        raw,
        collector_profile=deepcopy(value[2]),
    )
    assert canonical == value

    unsupported = _base(unsupported_source=True)
    raw_unsupported = canonical_cbor_encode(
        [
            unsupported[3][1],
            unsupported[4][:3],
            unsupported[5],
            unsupported[6],
            unsupported[7],
        ]
    )
    canonical_unsupported = canonicalize_native_diagnostic_transport(
        raw_unsupported,
        collector_profile=deepcopy(unsupported[2]),
    )
    assert canonical_unsupported == unsupported

    with pytest.raises(M0DiagnosticCensusError):
        canonicalize_native_diagnostic_transport(
            raw + b"\x00",
            collector_profile=deepcopy(value[2]),
        )


def test_maps_booleans_and_wrong_widths_fail_with_structural_code() -> None:
    value = _base()
    value[2] = {"collector_binary_sha256": ZERO}
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    value[5][0][1][0] = False
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    value[5][0][1] = [0, 0]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def _bundle_root(manifest: list[object]) -> bytes:
    return sha256(
        canonical_cbor_encode(
            [CANONICALIZER_BUNDLE_DOMAIN, 631302, 1, 1, manifest]
        )
    ).digest()


def test_python_canonicalizer_kind_and_exact_bundle_are_mandatory() -> None:
    value = _base()
    value[2][4] = 0
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    value[2][5] = ZERO
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    value[2][7][2] = value[2][7][2][:-1]
    value[2][6] = _bundle_root(value[2][7])
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    worker_row = next(
        row
        for row in value[2][7][2]
        if row[0] == CANONICALIZER_WORKER_ENTRY_PATH
    )
    worker_row[2] = ZERO
    value[2][6] = _bundle_root(value[2][7])
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_duplicate_subject_construct_and_count_mismatch_fail_closed() -> None:
    value = _base(unsupported_source=True)
    value[5].append(deepcopy(value[5][0]))
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base(unsupported_source=True)
    value[5][0][3].append(deepcopy(value[5][0][3][0]))
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base(unsupported_source=True)
    value[5][0][3].append([deepcopy(value[5][0][3][0][0]), "M0_OTHER_FAILURE"])
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    value[4][0][0] = 2
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_construct_keys_are_unique_across_the_entire_census_and_native_path() -> None:
    value = _base(unsupported_source=True)
    second_subject = _source_subject((1,), 2)
    shared_blocker = deepcopy(value[5][0][3][0])
    value[5].append(
        [second_subject, [0, 0, 0, 0, 0, []], 3, [shared_blocker]]
    )
    value[8].append([1, second_subject, shared_blocker[0], shared_blocker[1]])
    value[4][0] = [2, 0, 0, 2]
    value[4][3] = 2
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    raw = canonical_cbor_encode(
        [value[3][1], value[4][:3], value[5], value[6], value[7]]
    )
    with pytest.raises(M0DiagnosticCensusError) as raised:
        canonicalize_native_diagnostic_transport(
            raw,
            collector_profile=deepcopy(value[2]),
        )
    assert raised.value.code == M0_DIAGNOSTIC_INVENTORY_INCOMPLETE


def test_registry_projection_root_and_target_indices_fail_closed_on_corruption() -> None:
    value = _base()
    value[3][1][0][1] = "corrupt"
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    value[3][2] = ZERO
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    value[7][0][0][2][4] = [116]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_domain3_target_identity_and_qtid_are_bound_to_frozen_descriptors() -> None:
    value = _base()
    value[7][0][0][2][1] = "forged-name"
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    value[7][0][0][2][2] = "!"
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base()
    value[7][0][0][2][4] = []
    value[7][0][0][2][2] = "std::vector<"
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_runtime_summary_counts_globals_not_phases_and_keeps_constant_rows() -> None:
    value = _base()
    value[6] = [[_global(), 1, [0, 1, []], [0, 1, []]]]
    assert canonicalize_diagnostic_census(value)[4][1] == [1, 1, 0, 0]
    value[4][1] = [2, 2, 0, 0]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_template_exclusion_requires_exact_wire_proof_and_valid_specialization() -> None:
    pattern = _source_subject((0,), 10)
    specialization = _source_subject((1,), 20)
    value = _base()
    value[5] = [
        [
            pattern,
            [0, 0, 0, 1, 0, [1, 1, [], [1, [specialization]], []]],
            2,
            [],
        ],
        [specialization, [0, 0, 0, 0, 1, []], 1, []],
    ]
    value[7] = [[_instance(specialization, _definition(20, [0])), []]]
    value[4][0] = [2, 1, 1, 0]
    canonical = canonicalize_diagnostic_census(value)
    assert canonical[4][0] == [2, 1, 1, 0]

    malformed = deepcopy(value)
    malformed[5][0][1][5] = []
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, malformed)
    unproved = deepcopy(value)
    unproved[5][0][1][5][0] = 0
    _expect(M0_TEMPLATE_EMISSION_STATUS_UNPROVEN, unproved)
    unknown = deepcopy(value)
    unknown[5][0][1][5][3][1] = [_source_subject((9,), 99)]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, unknown)


def test_valid_discarded_template_pattern_is_absent_from_domain3() -> None:
    value = _discarded_source_value()
    canonical = canonicalize_diagnostic_census(value)
    discarded_subject = next(
        row[0]
        for row in canonical[5]
        if row[2] == 2
    )

    assert discarded_subject[1] == "FunctionDecl"
    assert all(
        not _contains_wire(domain3_row, discarded_subject)
        for domain3_row in canonical[7]
    )
    assert all(
        not _contains_wire(occurrence_row, discarded_subject)
        for _instance_key, occurrences in canonical[7]
        for occurrence_row in occurrences
    )


def test_template_proof_lists_must_arrive_strictly_canonical() -> None:
    pattern = _source_subject((0,), 10)
    first = _source_subject((1,), 20)
    second = _source_subject((2,), 30)
    ordered = sorted([first, second], key=canonical_cbor_encode)
    value = _base()
    value[5] = [
        [
            pattern,
            [0, 0, 0, 1, 0, [1, 1, [], [1, ordered], []]],
            2,
            [],
        ],
        [first, [0, 0, 0, 0, 1, []], 1, []],
        [second, [0, 0, 0, 0, 1, []], 1, []],
    ]
    value[7] = [
        [_instance(first, _definition(20, [0])), []],
        [_instance(second, _definition(30)), []],
    ]
    value[4][0] = [3, 2, 1, 0]
    canonical_pattern = next(
        row for row in canonicalize_diagnostic_census(value)[5] if row[0] == pattern
    )
    assert canonical_pattern[1][5][3][1] == ordered

    unsorted = deepcopy(value)
    unsorted[5][0][1][5][3][1] = list(reversed(ordered))
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, unsorted)
    targets = deepcopy(value)
    targets[5][0][1][5][2] = [1, 0]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, targets)


def test_domain1_to_domain3_join_collisions_fail_instead_of_overwriting() -> None:
    value = _base()
    value[5].append(
        [
            _source_subject((9,), 1),
            [0, 0, 0, 0, 0, []],
            1,
            [],
        ]
    )
    value[4][0] = [2, 2, 0, 0]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_duplicate_semantic_keys_are_valid_only_for_distinct_definition_instances() -> None:
    value = _base()
    first_instance = value[7][0][0]
    second_subject = _source_subject((9,), 1)
    second_instance = _instance(second_subject, deepcopy(first_instance[2]))
    value[5].append(
        [second_subject, [0, 0, 0, 0, 1, []], 1, []]
    )
    value[7].append([second_instance, []])
    value[4][0] = [2, 2, 0, 0]

    canonical = canonicalize_diagnostic_census(value)
    instances = [row[0] for row in canonical[7]]
    assert instances[0][2] == instances[1][2]
    assert instances[0] != instances[1]
    first_subject, second_subject = instances[0][1], instances[1][1]
    first_semantic, second_semantic = instances[0][2], instances[1][2]
    assert first_semantic[:4] == second_semantic[:4]  # kind, name, type, linkage
    assert first_semantic[5:] == second_semantic[5:]  # source path and exact span
    assert first_subject[1:] == second_subject[1:]  # same kind and source anchor
    assert first_subject[0] != second_subject[0]  # distinct structural identities

    duplicate = deepcopy(value)
    duplicate[7].append(deepcopy(duplicate[7][0]))
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, duplicate)


def test_domain3_rows_are_canonicalized_from_randomized_insertion_order() -> None:
    value = _two_instance_value(occurrences=True)
    canonical_bytes = encode_diagnostic_census(value)
    for seed in range(20):
        permuted = deepcopy(value)
        random.Random(seed).shuffle(permuted[7])
        for row in permuted[7]:
            random.Random(seed + 1000).shuffle(row[1])
        assert encode_diagnostic_census(permuted) == canonical_bytes


def test_domain3_blockers_use_full_instance_key_and_first_blocker_is_stable() -> None:
    value = _two_instance_value(occurrences=True)
    instance = value[7][0][0]
    occurrence = value[7][0][1][0][0]
    first_blocker = [_construct(11), "M0_FIRST"]
    second_blocker = [_construct(12), "M0_SECOND"]
    value[7][0][1] = [[occurrence, 3, [second_blocker, first_blocker]]]
    value[4][2] = [2, 1, 0, 1]
    value[4][3] = 2
    value[8] = [
        [3, instance, second_blocker[0], second_blocker[1]],
        [3, instance, first_blocker[0], first_blocker[1]],
    ]

    first = canonicalize_diagnostic_census(deepcopy(value))
    second = canonicalize_diagnostic_census(deepcopy(value))
    assert canonical_cbor_encode(first[8][0]) == canonical_cbor_encode(second[8][0])
    assert first[8][0][0] == 3
    assert first[8][0][1] == first[7][0][0]
    assert first[8][0][1][0] == 2
    assert first[8][0][1][2] == instance[2]


def test_first_blocker_bytes_match_across_fresh_isolated_python_processes() -> None:
    value = _base(unsupported_source=True)
    payload = canonical_cbor_encode(value)
    script = """
import sys
sys.path.insert(0, sys.argv[1])
from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_encode, canonical_cbor_decode
from evaluation_v6_3_1.m0_diagnostic_census import canonicalize_diagnostic_census

value = canonical_cbor_decode(sys.stdin.buffer.read())
canonical = canonicalize_diagnostic_census(value)
sys.stdout.buffer.write(canonical_cbor_encode(canonical[8][0]))
"""

    def run_worker() -> bytes:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-E",
                "-s",
                "-P",
                "-u",
                "-c",
                script,
                str(ROOT),
            ],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env={},
            check=False,
        )
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
        assert result.stderr == b""
        return result.stdout

    first = run_worker()
    second = run_worker()
    assert first == second
    assert first == canonical_cbor_encode(
        canonicalize_diagnostic_census(value)[8][0]
    )


def test_occurrence_rows_remain_attached_to_exact_colliding_definition_instance() -> None:
    value = _two_instance_value(occurrences=True)
    canonical = canonicalize_diagnostic_census(value)
    expected = {
        canonical_cbor_encode(row[0]): row[1][0][0]
        for row in value[7]
    }
    for row in canonical[7]:
        assert row[1][0][0] == expected[canonical_cbor_encode(row[0])]
        assert row[0][2] == value[7][0][0][2]


def test_missing_represented_domain1_row_is_rejected_in_isolation() -> None:
    value = _base()
    value[7] = []
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_two_distinct_domain3_rows_cannot_reference_one_source_subject() -> None:
    value = _base()
    subject = value[7][0][0][1]
    first_definition = value[7][0][0][2]
    second_definition = _definition(
        1,
        [1],
        name=TARGET_DESCRIPTORS[1][1],
        raw_type=TARGET_DESCRIPTORS[1][2],
    )
    value[7] = [
        [_instance(subject, first_definition), []],
        [_instance(subject, second_definition), []],
    ]
    value[4][2] = [0, 0, 0, 0]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_domain3_references_to_unsupported_and_discarded_domain1_rows_fail() -> None:
    unsupported = _base(unsupported_source=True)
    unsupported_subject = unsupported[5][0][0]
    unsupported[7].append([_instance(unsupported_subject, _definition(1, [0])), []])
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, unsupported)

    discarded = _discarded_source_value()
    discarded_subject = discarded[5][0][0]
    discarded[7].insert(0, [_instance(discarded_subject, _definition(10)), []])
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, discarded)


def test_old_absolute_path_and_domain3_join_wires_are_rejected() -> None:
    value = _base()
    value[5][0][0][0] = [0]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    value[6][0][0][8] = [1, 2]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    instance = value[7][0][0]
    value[7][0][0] = [instance[1], instance[2]]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    value[7][0][0][0] = 9
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    value[5][0][0][0][0] = 9
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_unknown_missing_and_pointer_like_subject_wires_are_rejected() -> None:
    value = _base()
    value[5][0][0] = [value[5][0][0][0], value[5][0][0][1]]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    value[5][0][0][0] = [9, [0]]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    value[5][0][0][0] = 0x00007FFF12345678
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    value[5][0][0][0] = b"\x00" * 8
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    value[7][0][0] = [value[7][0][0][0], value[7][0][0][1]]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    instance = value[7][0][0]
    value[7][0][0] = [9, instance[1], instance[2]]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base(unsupported_source=True)
    value[8][0][1] = _source_subject((99,), 999)
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base(unsupported_source=True)
    value[8][0] = [1, value[8][0][1], value[8][0][2]]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base(unsupported_source=True)
    value[8][0][1] = [value[8][0][1][0], value[8][0][1][1]]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_candidate_id_and_pointer_like_extra_fields_fail_by_wire_width() -> None:
    value = _base(unsupported_source=True)
    value[8][0].append(1234)
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base(unsupported_source=True)
    value[5][0][3][0].append("candidate_id")
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    value[7][0][0].append("pointer")
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_var_template_specialization_runtime_wire_is_exact() -> None:
    value = _base()
    value[6] = [
        [
            _global(kind="VarTemplateSpecializationDecl"),
            4,
            [1, 1, []],
            [1, 1, []],
        ]
    ]
    canonical = canonicalize_diagnostic_census(value)
    expected_global = [
        "VarTemplateSpecializationDecl",
        "g2",
        "int",
        1,
        [0],
        "/v631302/src/Export.cpp",
        2,
        3,
        [2, [1, 2]],
    ]
    assert canonical[6] == [
        [expected_global, 4, [1, 1, []], [1, 1, []]]
    ]
    assert canonical[4][1] == [1, 1, 0, 0]


def test_authenticated_join_and_structural_ast_paths_are_unique() -> None:
    value = _base()
    value[7][0][0][1] = _source_subject((9,), 1)
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    value[5].append(
        [_source_subject((0,), 2), [0, 0, 0, 0, 0, []], 1, []]
    )
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)

    value = _base()
    colliding_global = _global(3)
    colliding_global[8] = deepcopy(value[6][0][0][8])
    value[6].append([colliding_global, 1, [0, 1, []], [0, 1, []]])
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_blocker_reconstruction_is_exact() -> None:
    value = _base(unsupported_source=True)
    value[8] = []
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)
    value = _base(unsupported_source=True)
    value[8] = [[1, value[5][0][0], _construct(999), "M0_UNSUPPORTED_CALL"]]
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, value)


def test_canonicalizer_normalizes_collection_order_but_final_validator_rejects_it() -> None:
    value = _base(unsupported_source=True)
    second_blocker = [_construct(99), "M0_A"]
    value[5][0][3].append(second_blocker)
    value[8].append([1, value[5][0][0], second_blocker[0], second_blocker[1]])
    value[4][3] = 2
    canonical = canonicalize_diagnostic_census(value)
    canonical_bytes = canonical_cbor_encode(canonical)
    for seed in range(10):
        permuted = deepcopy(value)
        random.Random(seed).shuffle(permuted[5][0][3])
        random.Random(seed + 100).shuffle(permuted[8])
        assert encode_diagnostic_census(permuted) == canonical_bytes
    noncanonical = deepcopy(canonical)
    noncanonical[5][0][3].reverse()
    noncanonical[8].reverse()
    _expect(M0_DIAGNOSTIC_INVENTORY_INCOMPLETE, noncanonical, final=True)
    with pytest.raises(M0DiagnosticCensusError):
        decode_diagnostic_census(canonical_cbor_encode(noncanonical))


def test_vaarg_is_unsupported_while_unevaluated_requires_is_absent() -> None:
    value = _base()
    vaarg = _construct(101, "VAArgExpr")
    value[7][0][1] = [[vaarg, 3, [[vaarg, "M0_VAARG_UNSUPPORTED"]]]]
    value[4][2] = [1, 0, 0, 1]
    value[4][3] = 1
    value[8] = [[3, value[7][0][0], vaarg, "M0_VAARG_UNSUPPORTED"]]
    canonical = canonicalize_diagnostic_census(value)
    kinds = [row[0][1] for definition in canonical[7] for row in definition[1]]
    assert kinds == ["VAArgExpr"]
    assert "RequiresExpr" not in kinds


def _raw_transport(value: list[object]) -> bytes:
    return canonical_cbor_encode(
        [value[3][1], value[4][:3], value[5], value[6], value[7]]
    )


def test_exact_entry_callable_returns_bound_success_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    value = _base()
    bound_profile = canonical_cbor_encode(value[2])
    monkeypatch.setitem(
        census_module.__dict__,
        "V631302_BOUND_COLLECTOR_PROFILE_CBOR",
        bound_profile,
    )
    result = census_module.canonical_cbor_decode(
        canonicalize_diagnostic_census_v1(_raw_transport(value))
    )
    assert result[:3] == [631302, 1, 0]
    artifact = census_module.canonical_cbor_decode(result[3])
    assert canonical_cbor_encode(artifact[2]) == bound_profile
    assert artifact == value


def test_exact_entry_callable_distinguishes_structural_and_template_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = _base()
    monkeypatch.setitem(
        census_module.__dict__,
        "V631302_BOUND_COLLECTOR_PROFILE_CBOR",
        canonical_cbor_encode(value[2]),
    )
    assert census_module.canonical_cbor_decode(
        canonicalize_diagnostic_census_v1(b"not-cbor")
    ) == [631302, 1, 1, b""]

    pattern = _source_subject((0,), 10)
    specialization = _source_subject((1,), 20)
    value[5] = [
        [
            pattern,
            [0, 0, 0, 1, 0, [0, 1, [], [1, [specialization]], []]],
            2,
            [],
        ],
        [specialization, [0, 0, 0, 0, 1, []], 1, []],
    ]
    value[7] = [[_instance(specialization, _definition(20, [0])), []]]
    value[4][0] = [2, 1, 1, 0]
    result = census_module.canonical_cbor_decode(
        canonicalize_diagnostic_census_v1(_raw_transport(value))
    )
    assert result == [631302, 1, 2, b""]


def test_entry_source_has_only_verified_project_imports_and_no_profile_fallback() -> None:
    source = (ROOT / CANONICALIZER_ENTRY_MODULE_PATH).read_text(encoding="ascii")
    import_lines = [
        line.strip()
        for line in source.splitlines()
        if line.startswith("import ") or line.startswith("from ")
    ]
    assert import_lines == [
        "from __future__ import annotations",
        "from .m0_diagnostic_primitives import (",
    ]
    assert source.startswith("from __future__ import annotations\n")
    assert "V631302_BOUND_COLLECTOR_PROFILE_CBOR =" not in source


def test_real_entry_bundle_runs_in_fresh_isolated_worker() -> None:
    if not Path("/proc/self/exe").exists():
        pytest.skip("the frozen worker integration requires Linux /proc/self/exe")
    executable = Path("/proc/self/exe").read_bytes()
    if len(executable) != 6834488 or sha256(executable).digest() != PINNED_INTERPRETER_SHA256:
        pytest.skip("the frozen worker integration requires the pinned CPython image")
    value = _base()
    files = {
        row[0]: (ROOT / row[0]).read_bytes()
        for row in CANONICALIZER_BUNDLE_MANIFEST[2]
    }
    byte_rows = [
        [row[0], files[row[0]]] for row in CANONICALIZER_BUNDLE_MANIFEST[2]
    ]
    payload = canonical_cbor_encode(
        [631302, 1, value[2], byte_rows, _raw_transport(value)]
    )
    frame = b"V631DI01" + len(payload).to_bytes(8, "big") + payload
    worker = files[CANONICALIZER_WORKER_ENTRY_PATH]
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-E",
            "-s",
            "-P",
            "-B",
            "-u",
            "-X",
            "utf8",
            "-c",
            worker.decode("ascii"),
            "V631302_DIAGNOSTIC_WORKER_V1",
            CANONICALIZER_WORKER_ENTRY_PATH,
        ],
        input=frame,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env={},
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == b""
    assert result.stdout[:8] == b"V631DO01"
    size = int.from_bytes(result.stdout[8:16], "big")
    assert result.stdout[16:] == encode_diagnostic_census(value)
    assert size == len(result.stdout[16:])
