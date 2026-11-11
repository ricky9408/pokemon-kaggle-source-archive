from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_encode as reference_encode
from evaluation_v6_3_1.eir_prebinding import qtid_ascii_v1 as reference_qtid
from evaluation_v6_3_1.m0_diagnostic_primitives import (
    M0PrimitiveError,
    canonical_cbor_decode,
    canonical_cbor_encode,
    definition_instance_key_v2,
    definition_semantic_key_v1,
    qtid_ascii_v1,
    sha256_digest,
    subject_key,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evaluation_v6_3_1/m0_diagnostic_primitives.py"


def test_bundle_primitive_source_is_ascii_and_has_no_imports() -> None:
    raw = SOURCE.read_bytes()
    assert raw.decode("ascii").encode("ascii") == raw
    tree = ast.parse(raw, filename=str(SOURCE))
    assert not [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]


def test_bundle_primitive_executes_with_restricted_builtins() -> None:
    real_builtins = __builtins__
    if not isinstance(real_builtins, dict):
        real_builtins = vars(real_builtins)
    restricted = dict(real_builtins)
    for name in ("open", "compile", "eval", "exec", "input", "breakpoint", "help"):
        restricted.pop(name, None)
    namespace = {
        "__name__": "evaluation_v6_3_1.m0_diagnostic_primitives",
        "__package__": "evaluation_v6_3_1",
        "__file__": "v631302-bundle://evaluation_v6_3_1/m0_diagnostic_primitives.py",
        "__loader__": None,
        "__spec__": None,
        "__builtins__": restricted,
    }
    code = compile(SOURCE.read_bytes(), namespace["__file__"], "exec", dont_inherit=True, optimize=0)
    exec(code, namespace)
    assert namespace["sha256_digest"](b"abc") == hashlib.sha256(b"abc").digest()


@pytest.mark.parametrize(
    "raw",
    [b"", b"a", b"abc", bytes(range(64)), bytes(range(255)), b"x" * 1000],
)
def test_pure_sha256_matches_reference(raw: bytes) -> None:
    assert sha256_digest(raw) == hashlib.sha256(raw).digest()


@pytest.mark.parametrize(
    "value",
    [
        0,
        23,
        24,
        65536,
        b"",
        b"abc",
        "",
        "ascii",
        [],
        [631302, 1, [b"x", "y", 7], []],
    ],
)
def test_import_free_cbor_matches_reference_for_arrays_only_values(value: object) -> None:
    raw = canonical_cbor_encode(value)
    assert raw == reference_encode(value)
    assert canonical_cbor_decode(raw) == value


def test_import_free_cbor_rejects_trailing_nonascii_and_maps() -> None:
    with pytest.raises(M0PrimitiveError):
        canonical_cbor_decode(canonical_cbor_encode([1]) + b"\x00")
    with pytest.raises(M0PrimitiveError):
        canonical_cbor_encode("caf\N{LATIN SMALL LETTER E WITH ACUTE}")
    with pytest.raises(M0PrimitiveError):
        canonical_cbor_encode({"a": 1})


def test_import_free_cbor_rejects_self_referential_array() -> None:
    value: list[object] = []
    value.append(value)
    with pytest.raises(M0PrimitiveError):
        canonical_cbor_encode(value)


@pytest.mark.parametrize(
    "raw",
    [
        "int ()",
        "void (int, const char *)",
        "std::vector<int>",
        "int (*)(int)",
        "const unsigned long &&",
    ],
)
def test_import_free_qtid_matches_frozen_reference(raw: str) -> None:
    assert qtid_ascii_v1(raw) == reference_qtid(raw)


def test_import_free_qtid_matches_all_frozen_target_descriptors() -> None:
    artifact = json.loads(
        (
            ROOT
            / "strategy/evaluation_v6_3_1_entropy_static_closure_sourcebound_20260721.json"
        ).read_text(encoding="utf-8")
    )
    targets = artifact["details"]["compiler_derived_dispatch_proof"]["targets"]
    assert len(targets) == 116
    for row in targets:
        assert qtid_ascii_v1(row["qual_type"]) == reference_qtid(row["qual_type"])


def test_subject_key_validation_matches_required_shapes() -> None:
    source = [[[2, [1, 2]], "FunctionDecl", ["/v631302/src/fixture.cc", 10, 20]]]
    assert subject_key(1, source[0]) == source[0]
    semantic = [
        "FunctionDecl",
        "probe",
        "int ()",
        1,
        [],
        "/v631302/src/fixture.cc",
        10,
        20,
    ]
    definition = [2, source[0], semantic]
    assert definition_semantic_key_v1(semantic) == semantic
    assert definition_instance_key_v2(definition) == definition
    assert subject_key(3, definition) == definition
    broken = list(semantic)
    broken[3] = 0
    with pytest.raises(M0PrimitiveError):
        definition_semantic_key_v1(broken)

    with pytest.raises(M0PrimitiveError):
        subject_key(1, [[1, 2], "FunctionDecl", ["/v631302/src/fixture.cc", 10, 20]])
    with pytest.raises(M0PrimitiveError):
        subject_key(3, semantic)


@pytest.mark.parametrize(
    "kind",
    [
        "VarDecl",
        "VarTemplateSpecializationDecl",
        "VarTemplatePartialSpecializationDecl",
    ],
)
def test_tu_runtime_subject_preserves_concrete_variable_declaration_kind(
    kind: str,
) -> None:
    value = [
        kind,
        "variable_template_value<int>",
        "int",
        1,
        [],
        "/v631302/src/fixture.cc",
        10,
        20,
        [2, [1, 2, 3]],
    ]
    assert subject_key(2, value) == value


def test_tu_runtime_subject_rejects_unbound_declaration_kind() -> None:
    value = [
        "NamedDecl",
        "value",
        "int",
        1,
        [],
        "/v631302/src/fixture.cc",
        10,
        20,
        [2, [1]],
    ]
    with pytest.raises(M0PrimitiveError):
        subject_key(2, value)
