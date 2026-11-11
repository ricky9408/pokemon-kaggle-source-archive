from hashlib import sha256
import os
from pathlib import Path

import pytest

from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_encode
from evaluation_v6_3_1.eir_prebinding import (
    ENVIRONMENT,
    EIRPrebindingError,
    backend_matcher_root,
    external_terminal_root,
)
from evaluation_v6_3_1 import eir_state3_semantics as semantics


PROTOCOL_ID = 631302
PROFILE_VERSION = 1
PROFILE_DOMAIN = b"V631302/STATE3_EXECUTION_PROFILE\0"
ALLOWLIST_DOMAIN = b"V631302/STATE3_LOCAL_TRUST_ALLOWLIST_ROOT\0"
TU_CONTENT_DOMAIN = b"V631302/TU_CONTENT_ROOT\0"
TU_SEMANTICS_DOMAIN = b"V631302/TU_SEMANTICS_ROOT\0"
LINKAGE_DOMAIN = b"V631302/LINKAGE_SCOPE_ID\0"


def _digest(byte: int) -> bytes:
    return bytes([byte]) * 32


def _domain_hash(domain: bytes, value: list[object]) -> bytes:
    return sha256(domain + canonical_cbor_encode(value)).digest()


def _expect_error(call, *codes: str) -> None:
    with pytest.raises(EIRPrebindingError) as raised:
        call()
    assert isinstance(raised.value.code, str)
    assert raised.value.code
    if codes:
        assert raised.value.code in codes


def _profile() -> list[object]:
    return [
        PROTOCOL_ID,
        PROFILE_VERSION,
        2,
        _digest(1),  # expected source root
        _digest(2),  # expected target root
        _digest(3),  # expected static-closure digest
        _digest(4),  # toolchain/runtime root
        _digest(5),  # compiler digest
        _digest(6),  # extractor digest
        _digest(7),  # compiler-semantics root
        _digest(8),  # backend matcher root
        _digest(9),  # external-terminal root
    ]


def _allowlist() -> list[object]:
    profile = _profile()
    return [
        PROTOCOL_ID,
        PROFILE_VERSION,
        [[_domain_hash(PROFILE_DOMAIN, profile), profile, _digest(10), _digest(11)]],
    ]


def _effective_frontend_state() -> list[object]:
    return [
        [
            "/v631302/toolchain/bin/clang",
            "-cc1",
            "-triple",
            "x86_64-pc-linux-gnu",
        ],
        "x86_64-pc-linux-gnu",
        2,
        "c++20",
        "/v631302/toolchain/lib/clang",
        "/v631302/toolchain/sysroot",
        0,
        0,
        0,
        0,
        0,
    ]


def _registries(
    runtime_root: bytes,
) -> tuple[bytes, bytes, bytes, list[object], list[object], list[object]]:
    semantics_root = _digest(40)
    backend_a = ["FunctionDecl", "a", "int ()", "int()", 1, bytes(32)]
    backend_b = ["FunctionDecl", "b", "int ()", "int()", 1, bytes(32)]
    builtin = ["FunctionDecl", "c", "int ()", "int()", 1, bytes(32)]
    backend_registry = [
        1,
        semantics_root,
        [
            [1, 1, 1, "CallExpr", backend_a],
            [2, 1, 1, "CallExpr", backend_b],
        ],
    ]
    matcher_root = backend_matcher_root(backend_registry)
    unordered_entries = [
        [0, 1, backend_a, 1, 1, matcher_root],
        [0, 1, backend_b, 2, 1, matcher_root],
        [0, 2, builtin, 0, 3, runtime_root],
    ]
    entries = sorted(unordered_entries, key=lambda row: canonical_cbor_encode(row[2]))
    for ordinal, entry in enumerate(entries):
        entry[0] = ordinal
    terminal_registry = [1, semantics_root, matcher_root, entries]
    terminal_root = external_terminal_root(terminal_registry)
    return (
        semantics_root,
        matcher_root,
        terminal_root,
        backend_registry,
        terminal_registry,
        builtin,
    )


def _tu_parts() -> dict[str, object]:
    source_root = _digest(17)
    runtime_root = _digest(18)
    primary = [
        1,
        "/v631302/src/main.cc",
        3,
        sha256(b"abc").digest(),
        1,
    ]
    dependencies = [
        [
            0,
            1,
            "/v631302/src/header.h",
            3,
            sha256(b"xyz").digest(),
            1,
        ],
        [
            1,
            2,
            "/v631302/toolchain/include/c++",
            3,
            sha256(b"lib").digest(),
            2,
        ],
    ]
    predefines = [4, sha256(b"prep").digest()]
    virtual = [[0, 1, "<built-in>", 1, sha256(b"v").digest(), 1]]
    content = [
        PROTOCOL_ID,
        1,
        source_root,
        runtime_root,
        7,
        primary,
        dependencies,
        predefines,
        virtual,
    ]
    content_root = _domain_hash(TU_CONTENT_DOMAIN, content)
    semantics_value = [
        PROTOCOL_ID,
        1,
        source_root,
        runtime_root,
        _digest(19),
        _digest(20),
        _digest(21),
        7,
        "/v631302/src/main.cc",
        "/v631302/work",
        "/v631302/src",
        "/v631302/toolchain",
        [list(pair) for pair in ENVIRONMENT],
        ["/v631302/toolchain/bin/clang", "-c", "/v631302/src/main.cc"],
        ["/v631302/toolchain/bin/extractor", "/v631302/src/main.cc"],
        _effective_frontend_state(),
    ]
    semantics_root = _domain_hash(TU_SEMANTICS_DOMAIN, semantics_value)
    linkage_value = [
        PROTOCOL_ID,
        1,
        source_root,
        _digest(22),
        7,
        "/v631302/src/main.cc",
        content_root,
        semantics_root,
    ]
    return {
        "source_root": source_root,
        "runtime_root": runtime_root,
        "primary": primary,
        "dependencies": dependencies,
        "predefines": predefines,
        "virtual": virtual,
        "content": content,
        "content_root": content_root,
        "semantics_value": semantics_value,
        "semantics_root": semantics_root,
        "linkage_value": linkage_value,
    }


def _observation(
    *,
    coverage: list[int] | None = None,
    definitions: list[list[object]] | None = None,
) -> list[object]:
    state = _effective_frontend_state()
    return [
        PROTOCOL_ID,
        2,
        7,
        "/v631302/src/main.cc",
        state,
        [1, "/v631302/src/main.cc", 1],
        [[0, 1, "/v631302/src/header.h", 1]],
        b"#define __cplusplus 202002L\n",
        [[0, 1, "<built-in>", b"__cplusplus 202002L", 1]],
        [] if definitions is None else definitions,
        [
            2,
            2,
            2,
            2,
            1,
            1,
            0 if definitions is None else len(definitions),
            0 if definitions is None else len(definitions),
            0,
            0,
            0,
            0,
            0,
            0,
        ] if coverage is None else coverage,
    ]


def test_source_tree_sha256_has_independent_empty_and_manual_vectors(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert semantics.source_tree_sha256(empty) == bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    (empty / "z.txt").write_bytes(b"")
    (empty / "a.txt").write_bytes(b"abc")
    assert semantics.source_tree_sha256(empty) == bytes.fromhex(
        "45206ab473682c1b48f058d8658e63a0c0a5d0173e33f74698542879da5be432"
    )

    root_fd = os.open(empty, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert semantics.source_tree_sha256_fd(root_fd) == semantics.source_tree_sha256(empty)
        assert os.fstat(root_fd).st_ino == os.stat(empty).st_ino
    finally:
        os.close(root_fd)


def test_source_tree_sha256_sorts_raw_utf8_paths_and_is_creation_order_independent(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "é").write_bytes(b"E")
    (root / "b").write_bytes(b"B")
    expected = bytes.fromhex(
        "e537f49bf608c544de29b1f1c886cee4cee2efc70e059edb69c473ec719213ed"
    )
    assert semantics.source_tree_sha256(root) == expected

    (root / "b").unlink()
    (root / "é").unlink()
    (root / "b").write_bytes(b"B")
    (root / "é").write_bytes(b"E")
    assert semantics.source_tree_sha256(root) == expected


def test_source_tree_sha256_rejects_symlinks_and_nonregular_entries(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "real").write_bytes(b"real")
    os.symlink("real", root / "alias")
    _expect_error(
        lambda: semantics.source_tree_sha256(root),
        "SOURCE_TREE_SYMLINK_FORBIDDEN",
    )

    (root / "alias").unlink()
    try:
        os.mkfifo(root / "pipe")
    except (AttributeError, NotImplementedError, OSError):
        pytest.skip("named pipes are unavailable on this filesystem")
    _expect_error(
        lambda: semantics.source_tree_sha256(root),
        "SOURCE_TREE_NONREGULAR_ENTRY",
    )


@pytest.mark.parametrize("replacement", [b"after!", b"after much longer"])
def test_source_tree_sha256_rechecks_early_files_after_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: bytes
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    first = root / "a"
    first.write_bytes(b"before")
    (root / "b").write_bytes(b"stable")
    original = semantics._read_source_file

    def mutate_after_read(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[1] == "a":
            first.write_bytes(replacement)
        return result

    monkeypatch.setattr(semantics, "_read_source_file", mutate_after_read)
    _expect_error(
        lambda: semantics.source_tree_sha256(root),
        "SOURCE_TREE_RACE_DETECTED",
    )


def test_execution_profile_validation_and_manual_profile_id_vector() -> None:
    profile = _profile()
    assert semantics.validate_state3_execution_profile(profile) == profile
    assert semantics.state3_execution_profile_id(profile) == bytes.fromhex(
        "73b04f4ad2e1db2f13fe3c2eb944201c36344b28341180626db84676dca7e3a8"
    )

    for index, bad in ((0, 631301), (1, 2), (2, 1), (3, b"short")):
        mutated = list(profile)
        mutated[index] = bad
        _expect_error(lambda value=mutated: semantics.validate_state3_execution_profile(value))

    mutated = list(profile)
    mutated.append(_digest(23))
    _expect_error(lambda: semantics.validate_state3_execution_profile(mutated))
    assert semantics.validate_state3_execution_profile(tuple(profile)) == profile
    _expect_error(lambda: semantics.state3_execution_profile_id(mutated))


def test_local_trust_allowlist_validates_profiles_and_manual_root_vector() -> None:
    allowlist = _allowlist()
    assert semantics.validate_state3_local_trust_allowlist(allowlist) == allowlist
    assert semantics.state3_local_trust_allowlist_root(allowlist) == bytes.fromhex(
        "a7aa38303e6a36c9a3d4050cf1a33507fe60977eb4fa79c31d44e616758f98f8"
    )

    duplicate = [
        allowlist[0],
        allowlist[1],
        [allowlist[2][0], allowlist[2][0]],
    ]
    _expect_error(lambda: semantics.validate_state3_local_trust_allowlist(duplicate))

    second_profile = _profile()
    second_profile[3] = _digest(12)
    second = [
        _domain_hash(PROFILE_DOMAIN, second_profile),
        second_profile,
        _digest(13),
        _digest(14),
    ]
    reversed_entries = [allowlist[2][0], second]
    _expect_error(
        lambda: semantics.validate_state3_local_trust_allowlist(
            [PROTOCOL_ID, PROFILE_VERSION, reversed_entries]
        )
    )

    conflicting = list(allowlist[2][0])
    conflicting[1] = list(conflicting[1])
    conflicting[1][3] = _digest(99)
    _expect_error(
        lambda: semantics.validate_state3_local_trust_allowlist(
            [PROTOCOL_ID, PROFILE_VERSION, [allowlist[2][0], conflicting]]
        )
    )


def test_tu_content_root_has_manual_vector_and_rejects_bad_dependency_order() -> None:
    parts = _tu_parts()
    assert semantics.tu_content_root(
        source_root=parts["source_root"],
        toolchain_runtime_root=parts["runtime_root"],
        tu_ordinal=7,
        primary_input_commitment=parts["primary"],
        dependency_commitments=parts["dependencies"],
        predefines_commitment=parts["predefines"],
        virtual_input_commitments=parts["virtual"],
    ) == bytes.fromhex("be5b51a207323fab9a7af76b8f1f1b9e78fd317082cfbd32702da9900d17131d")

    reversed_dependencies = list(reversed(parts["dependencies"]))
    _expect_error(
        lambda: semantics.tu_content_root(
            source_root=parts["source_root"],
            toolchain_runtime_root=parts["runtime_root"],
            tu_ordinal=7,
            primary_input_commitment=parts["primary"],
            dependency_commitments=reversed_dependencies,
            predefines_commitment=parts["predefines"],
            virtual_input_commitments=parts["virtual"],
        )
    )

    duplicate = [list(parts["dependencies"][0]), list(parts["dependencies"][0])]
    _expect_error(
        lambda: semantics.tu_content_root(
            source_root=parts["source_root"],
            toolchain_runtime_root=parts["runtime_root"],
            tu_ordinal=7,
            primary_input_commitment=parts["primary"],
            dependency_commitments=duplicate,
            predefines_commitment=parts["predefines"],
            virtual_input_commitments=parts["virtual"],
        )
    )


def test_tu_content_root_rejects_work_inputs_and_invalid_activation_counts() -> None:
    parts = _tu_parts()
    bad_primary = list(parts["primary"])
    bad_primary[1] = "/v631302/work/input.cc"
    _expect_error(
        lambda: semantics.tu_content_root(
            source_root=parts["source_root"],
            toolchain_runtime_root=parts["runtime_root"],
            tu_ordinal=7,
            primary_input_commitment=bad_primary,
            dependency_commitments=parts["dependencies"],
            predefines_commitment=parts["predefines"],
            virtual_input_commitments=parts["virtual"],
        )
    )

    bad_dependency = [list(row) for row in parts["dependencies"]]
    bad_dependency[0][5] = 0
    _expect_error(
        lambda: semantics.tu_content_root(
            source_root=parts["source_root"],
            toolchain_runtime_root=parts["runtime_root"],
            tu_ordinal=7,
            primary_input_commitment=parts["primary"],
            dependency_commitments=bad_dependency,
            predefines_commitment=parts["predefines"],
            virtual_input_commitments=parts["virtual"],
        )
    )


def test_effective_frontend_state_requires_cc1_cxx_and_zero_dynamic_features() -> None:
    state = _effective_frontend_state()
    assert semantics.validate_effective_frontend_state(state) == state

    for bad_argv in (
        ["/v631302/toolchain/bin/clang", "-c"],
        ["/v631302/toolchain/bin/clang", "-cc1", "-march=native"],
        ["/v631302/toolchain/bin/clang", "-cc1", "-mcpu=native"],
        ["/v631302/toolchain/bin/clang", "-cc1", "-mtune=native"],
        ["/v631302/toolchain/bin/clang", "-cc1", "-march=native=bad"],
    ):
        mutated = list(state)
        mutated[0] = bad_argv
        _expect_error(lambda value=mutated: semantics.validate_effective_frontend_state(value))

    for index in (6, 7, 8, 9, 10):
        mutated = list(state)
        mutated[index] = 1
        _expect_error(lambda value=mutated: semantics.validate_effective_frontend_state(value))

    mutated = list(state)
    mutated[2] = 1
    _expect_error(lambda: semantics.validate_effective_frontend_state(mutated))

    mutated = list(state)
    mutated[6] = False
    _expect_error(lambda: semantics.validate_effective_frontend_state(mutated))


def test_tu_semantics_root_and_linkage_scope_have_manual_vectors() -> None:
    parts = _tu_parts()
    state = _effective_frontend_state()
    assert semantics.tu_semantics_root(
        source_root=parts["source_root"],
        toolchain_runtime_root=parts["runtime_root"],
        compiler_binary_sha256=_digest(19),
        extractor_binary_sha256=_digest(20),
        compiler_semantics_root=_digest(21),
        tu_ordinal=7,
        primary_source_virtual_path="/v631302/src/main.cc",
        working_directory="/v631302/work",
        source_mount="/v631302/src",
        toolchain_mount="/v631302/toolchain",
        environment=[list(pair) for pair in ENVIRONMENT],
        compiler_command=["/v631302/toolchain/bin/clang", "-c", "/v631302/src/main.cc"],
        extractor_command=["/v631302/toolchain/bin/extractor", "/v631302/src/main.cc"],
        effective_frontend_state=state,
    ) == parts["semantics_root"]

    content_root = parts["content_root"]
    semantics_root = parts["semantics_root"]
    assert semantics.linkage_scope_id(
        source_root=parts["source_root"],
        target_root=_digest(22),
        tu_ordinal=7,
        primary_source_virtual_path="/v631302/src/main.cc",
        tu_content_root=content_root,
        tu_semantics_root=semantics_root,
    ) == bytes.fromhex("eb0902ddd1d8afbc240fe8e7bd42fc258b0fb111bff8c6577eb9658ef5b40be5")


def test_tu_semantics_root_rejects_native_flags_and_work_semantic_inputs() -> None:
    parts = _tu_parts()
    kwargs = dict(
        source_root=parts["source_root"],
        toolchain_runtime_root=parts["runtime_root"],
        compiler_binary_sha256=_digest(19),
        extractor_binary_sha256=_digest(20),
        compiler_semantics_root=_digest(21),
        tu_ordinal=7,
        primary_source_virtual_path="/v631302/src/main.cc",
        working_directory="/v631302/work",
        source_mount="/v631302/src",
        toolchain_mount="/v631302/toolchain",
        environment=[list(pair) for pair in ENVIRONMENT],
        compiler_command=["/v631302/toolchain/bin/clang", "-c", "/v631302/src/main.cc"],
        extractor_command=["/v631302/toolchain/bin/extractor", "/v631302/src/main.cc"],
        effective_frontend_state=_effective_frontend_state(),
    )
    for flag in ("-march=native", "-mcpu=native", "-mtune=native", "-march=native=1"):
        bad = dict(kwargs)
        bad["compiler_command"] = [kwargs["compiler_command"][0], flag]
        _expect_error(lambda bad=bad: semantics.tu_semantics_root(**bad))

    bad = dict(kwargs)
    bad["primary_source_virtual_path"] = "/v631302/work/generated.cc"
    _expect_error(lambda: semantics.tu_semantics_root(**bad))


def test_observation_v2_accepts_exact_coverage_and_is_structural_only() -> None:
    observation = _observation()
    checked = semantics.validate_extractor_tu_observation_v2(observation)
    assert checked == observation
    assert isinstance(checked, list)
    assert checked[1] == 2
    assert checked[-1][-4:] == [0, 0, 0, 0]
    assert "authority" not in repr(checked).lower()


def test_observation_v2_rejects_bad_versions_primary_rows_and_coverage_width() -> None:
    observation = _observation()
    for index, bad in ((0, 631301), (1, 1), (2, -1), (3, "/v631302/work/main.cc")):
        mutated = list(observation)
        mutated[index] = bad
        _expect_error(lambda value=mutated: semantics.validate_extractor_tu_observation_v2(value))

    bad_primary = list(observation)
    bad_primary[5] = [2, "/v631302/src/main.cc", 1]
    _expect_error(lambda: semantics.validate_extractor_tu_observation_v2(bad_primary))

    bad_dependencies = list(observation)
    bad_dependencies[6] = [
        [0, 1, "/v631302/src/header.h", 1],
        [0, 1, "/v631302/src/other.h", 1],
    ]
    _expect_error(lambda: semantics.validate_extractor_tu_observation_v2(bad_dependencies))

    bad_coverage = list(observation)
    bad_coverage[-1] = [1] * 14
    _expect_error(lambda: semantics.validate_extractor_tu_observation_v2(bad_coverage))

    bad_coverage = list(observation)
    bad_coverage[-1] = [1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]
    _expect_error(lambda: semantics.validate_extractor_tu_observation_v2(bad_coverage))

    bad_coverage = list(observation)
    bad_coverage[-1] = [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0]
    _expect_error(lambda: semantics.validate_extractor_tu_observation_v2(bad_coverage))

    bad_virtuals = list(observation)
    bad_virtuals[8] = [
        [0, 1, "<built-in>", b"__cplusplus 202002L", 1],
        [0, 1, "<command-line>", b"-DTEST", 1],
    ]
    _expect_error(lambda: semantics.validate_extractor_tu_observation_v2(bad_virtuals))


def test_observation_v2_checks_definition_and_invocation_order_and_zero_time_builtins() -> None:
    descriptor = ["FunctionDecl", "helper", "void ()", 1, 1]
    invocation = [0, [0, 1], 1, 1, [descriptor]]
    definition = [
        0,
        "FunctionDecl",
        "main",
        "int ()",
        1,
        [0],
        "/v631302/src/main.cc",
        0,
        24,
        [invocation],
    ]
    observation = _observation(
        definitions=[definition],
        coverage=[2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
    )
    assert semantics.validate_extractor_tu_observation_v2(observation) == observation

    bad = _observation(
        definitions=[list(definition)],
        coverage=[2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
    )
    bad[9][0][7] = 24
    bad[9][0][8] = 24
    _expect_error(lambda: semantics.validate_extractor_tu_observation_v2(bad))

    bad = _observation(
        definitions=[list(definition)],
        coverage=[2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
    )
    bad[9][0][9] = [[1, [0], 1, 1, [descriptor]]]
    _expect_error(lambda: semantics.validate_extractor_tu_observation_v2(bad))

    bad = _observation(
        definitions=[list(definition)],
        coverage=[2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1],
    )
    _expect_error(lambda: semantics.validate_extractor_tu_observation_v2(bad))


def test_occurrence_validation_uses_closed_codes_and_canonical_descriptor_order() -> None:
    first = ["FunctionDecl", "a", "void ()", 1, 1]
    second = ["FunctionDecl", "b", "void ()", 1, 1]
    ordered = sorted([first, second], key=canonical_cbor_encode)
    rows = [[0, [], 1, 2, ordered]]
    assert semantics.validate_invocation_occurrences(rows) == rows

    duplicate = [[0, [], 1, 2, [first, first]]]
    _expect_error(
        lambda: semantics.validate_invocation_occurrences(duplicate),
        "CALLEE_DESCRIPTOR_DUPLICATE",
    )

    reversed_rows = [[0, [], 1, 2, list(reversed(ordered))]]
    _expect_error(
        lambda: semantics.validate_invocation_occurrences(reversed_rows),
        "CALLEE_DESCRIPTOR_ORDER_INVALID",
    )

    invalid_kind = [[0, [], 9, 1, [first]]]
    _expect_error(
        lambda: semantics.validate_invocation_occurrences(invalid_kind),
        "INVOCATION_KIND_INVALID",
    )


@pytest.mark.parametrize(("origin", "kind"), ((2, 1), (3, 8)))
def test_standalone_validators_reject_unauthenticated_terminal_origins(
    origin: int,
    kind: int,
) -> None:
    descriptor = ["FunctionDecl", "external", "void ()", 1, origin]
    _expect_error(
        lambda: semantics.validate_callee_descriptor(descriptor),
        "CALLEE_TERMINAL_CONTEXT_REQUIRED",
    )
    _expect_error(
        lambda: semantics.validate_invocation_occurrences([[0, [], kind, 1, [descriptor]]]),
        "CALLEE_TERMINAL_CONTEXT_REQUIRED",
    )


def test_occurrence_reduction_groups_duplicate_facts_into_prebinding_rows() -> None:
    helper_id = _digest(30)
    scope_id = _digest(31)
    descriptor = ["FunctionDecl", "helper", "void ()", 1, 1]
    occurrences = [
        [0, [0, 1], 1, 1, [descriptor]],
        [1, [0, 1], 1, 1, [descriptor]],
    ]
    declaration_key = ["FunctionDecl", "helper", "void ()", "void()", 1, bytes(32)]
    (
        semantics_root,
        matcher_root,
        terminal_root,
        backend_registry,
        terminal_registry,
        _,
    ) = _registries(_digest(32))
    reduced = semantics.reduce_invocation_occurrences(
        occurrences,
        current_linkage_scope_id=scope_id,
        source_definition_refs=[[declaration_key, [1, helper_id]]],
        backend_matcher_registry=backend_registry,
        external_terminal_registry=terminal_registry,
        compiler_semantics_root=semantics_root,
        expected_backend_matcher_root=matcher_root,
        expected_external_terminal_root=terminal_root,
        toolchain_runtime_root=_digest(32),
    )
    assert reduced == [[0, [0, 1], 0, 1, 1, 2, [[1, helper_id]]]]


def test_occurrence_reduction_enforces_terminal_origin_and_builtin_evidence() -> None:
    scope_id = _digest(31)
    runtime_root = _digest(32)
    (
        semantics_root,
        matcher_root,
        terminal_root,
        backend_registry,
        terminal_registry,
        declaration,
    ) = _registries(runtime_root)
    descriptor = [declaration[0], declaration[1], declaration[2], 1, 3]
    terminal_ordinal = next(
        entry[0] for entry in terminal_registry[3] if entry[2] == declaration
    )
    reduced = semantics.reduce_invocation_occurrences(
        [[0, [], 8, 1, [descriptor]]],
        current_linkage_scope_id=scope_id,
        source_definition_refs=[],
        backend_matcher_registry=backend_registry,
        external_terminal_registry=terminal_registry,
        compiler_semantics_root=semantics_root,
        expected_backend_matcher_root=matcher_root,
        expected_external_terminal_root=terminal_root,
        toolchain_runtime_root=runtime_root,
    )
    assert reduced == [[0, [], 0, 8, 1, 1, [[2, terminal_ordinal]]]]

    authenticated = next(entry for entry in terminal_registry[3] if entry[1] == 1)
    authenticated_declaration = authenticated[2]
    authenticated_descriptor = [
        authenticated_declaration[0],
        authenticated_declaration[1],
        authenticated_declaration[2],
        authenticated_declaration[4],
        2,
    ]
    reduced_authenticated = semantics.reduce_invocation_occurrences(
        [[0, [], 1, 1, [authenticated_descriptor]]],
        current_linkage_scope_id=scope_id,
        source_definition_refs=[],
        backend_matcher_registry=backend_registry,
        external_terminal_registry=terminal_registry,
        compiler_semantics_root=semantics_root,
        expected_backend_matcher_root=matcher_root,
        expected_external_terminal_root=terminal_root,
        toolchain_runtime_root=runtime_root,
    )
    assert reduced_authenticated == [
        [0, [], 0, 1, 1, 1, [[2, authenticated[0]]]]
    ]

    wrong_registry = [
        terminal_registry[0],
        terminal_registry[1],
        terminal_registry[2],
        [list(entry) for entry in terminal_registry[3]],
    ]
    next(entry for entry in wrong_registry[3] if entry[2] == declaration)[5] = _digest(33)
    _expect_error(
        lambda: semantics.reduce_invocation_occurrences(
            [[0, [], 8, 1, [descriptor]]],
            current_linkage_scope_id=scope_id,
            source_definition_refs=[],
            backend_matcher_registry=backend_registry,
            external_terminal_registry=wrong_registry,
            compiler_semantics_root=semantics_root,
            expected_backend_matcher_root=matcher_root,
            expected_external_terminal_root=terminal_root,
            toolchain_runtime_root=runtime_root,
        ),
        "TERMINAL_COHERENCE_INVALID",
    )

    forged_backend_registry = [
        terminal_registry[0],
        terminal_registry[1],
        terminal_registry[2],
        [list(entry) for entry in terminal_registry[3]],
    ]
    next(entry for entry in forged_backend_registry[3] if entry[1] == 1)[3] = 65535
    _expect_error(
        lambda: semantics.reduce_invocation_occurrences(
            [[0, [], 8, 1, [descriptor]]],
            current_linkage_scope_id=scope_id,
            source_definition_refs=[],
            backend_matcher_registry=backend_registry,
            external_terminal_registry=forged_backend_registry,
            compiler_semantics_root=semantics_root,
            expected_backend_matcher_root=matcher_root,
            expected_external_terminal_root=terminal_root,
            toolchain_runtime_root=runtime_root,
        ),
        "TERMINAL_COHERENCE_INVALID",
    )

    substituted_backend_registry = [
        backend_registry[0],
        backend_registry[1],
        [list(entry) for entry in backend_registry[2]],
    ]
    substituted_backend_registry[2][0][3] = "CXXMemberCallExpr"
    _expect_error(
        lambda: semantics.reduce_invocation_occurrences(
            [[0, [], 8, 1, [descriptor]]],
            current_linkage_scope_id=scope_id,
            source_definition_refs=[],
            backend_matcher_registry=substituted_backend_registry,
            external_terminal_registry=terminal_registry,
            compiler_semantics_root=semantics_root,
            expected_backend_matcher_root=matcher_root,
            expected_external_terminal_root=terminal_root,
            toolchain_runtime_root=runtime_root,
        ),
        "PREBINDING_ROOT_MISMATCH",
    )

    _expect_error(
        lambda: semantics.reduce_invocation_occurrences(
            [[0, [], 8, 1, [descriptor]]],
            current_linkage_scope_id=scope_id,
            source_definition_refs=[],
            backend_matcher_registry=backend_registry,
            external_terminal_registry=terminal_registry,
            compiler_semantics_root=semantics_root,
            expected_backend_matcher_root=matcher_root,
            expected_external_terminal_root=_digest(99),
            toolchain_runtime_root=runtime_root,
        ),
        "PREBINDING_ROOT_MISMATCH",
    )


def test_observation_v2_does_not_mutate_input() -> None:
    observation = _observation()
    before = repr(observation)
    checked = semantics.validate_extractor_tu_observation_v2(observation)
    assert repr(observation) == before
    assert checked == observation
