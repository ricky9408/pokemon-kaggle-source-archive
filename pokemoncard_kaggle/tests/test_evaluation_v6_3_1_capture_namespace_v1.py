from copy import deepcopy
from hashlib import sha256

import pytest

from evaluation_v6_3_1.capture_namespace_v1 import (
    AGENT_MODIFICATION_AUTHORITY,
    AUTHORITY,
    CALIBRATION_UPLOAD_AUTHORITY,
    CAPTURE_NAMESPACE_CANONICAL_ENCODING,
    CAPTURE_NAMESPACE_DIGEST_INVALID,
    CAPTURE_NAMESPACE_INVALID_TYPE,
    CAPTURE_NAMESPACE_MANIFEST_V1,
    CAPTURE_NAMESPACE_MODE_INVALID,
    CAPTURE_NAMESPACE_ORDER_INVALID,
    CAPTURE_NAMESPACE_PATH_INVALID,
    CAPTURE_NAMESPACE_ROLE_INVALID,
    CAPTURE_NAMESPACE_ROOT_MISMATCH,
    CAPTURE_NAMESPACE_SCHEMA_INVALID,
    CLANG_CPP_IMPLEMENTATION,
    COLLECTOR_EXECUTABLE,
    DRIVER_AUXILIARY,
    ELF_INTERPRETER,
    ENGINE_WIRING_AUTHORITY,
    HOLDOUT_ACCESS_AUTHORITY,
    PERMIT_AUTHORITY,
    PRIMARY_SOURCE,
    PRODUCTION_UPLOAD_AUTHORITY,
    RUNTIME_DEPENDENCY,
    SEALED_HOLDOUT_ACCESS_AUTHORITY,
    SOURCE_INPUT,
    UPLOAD_AUTHORITY,
    capture_execution_namespace_root_v1,
    capture_runtime_root_v1,
    capture_source_root_v1,
    decode_capture_namespace_manifest_v1,
    derive_capture_namespace_roots_v1,
    encode_capture_namespace_manifest_v1,
    validate_capture_namespace_manifest_v1,
    validate_capture_namespace_roots_v1,
)
from evaluation_v6_3_1.eir_prebinding import EIRPrebindingError, eir_canonical_cbor_encode


def _digest(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _manifest() -> list[object]:
    return [
        CAPTURE_NAMESPACE_MANIFEST_V1,
        "work",
        "src/Export.cpp",
        ["/v631302/src", "/v631302/work", ["clang", "-fsyntax-only"]],
        [
            ["bin/collector", [COLLECTOR_EXECUTABLE], 0o555, 17, _digest("collector")],
            ["lib/ld-linux-x86-64.so.2", [ELF_INTERPRETER], 0o444, 19, _digest("loader")],
            ["lib/libclang-cpp.so.16", [CLANG_CPP_IMPLEMENTATION, RUNTIME_DEPENDENCY], 0o444, 21, _digest("clang")],
            ["src/Export.cpp", [PRIMARY_SOURCE, SOURCE_INPUT], 0o444, 23, _digest("primary")],
            ["src/driver.rsp", [DRIVER_AUXILIARY], 0o444, 29, _digest("driver")],
        ],
    ]


def _error(code: str, function, *args) -> None:
    with pytest.raises(EIRPrebindingError) as raised:
        function(*args)
    assert raised.value.code == code


def test_valid_manifest_round_trips_and_roots_are_domain_separated() -> None:
    manifest = _manifest()
    assert validate_capture_namespace_manifest_v1(manifest) == manifest
    encoded = encode_capture_namespace_manifest_v1(manifest)
    assert decode_capture_namespace_manifest_v1(encoded) == manifest

    roots = derive_capture_namespace_roots_v1(manifest)
    assert roots.source_root == capture_source_root_v1(manifest)
    assert roots.runtime_root == capture_runtime_root_v1(manifest)
    assert roots.execution_namespace_root == capture_execution_namespace_root_v1(manifest)
    assert len({roots.source_root, roots.runtime_root, roots.execution_namespace_root}) == 3
    assert validate_capture_namespace_roots_v1(manifest, roots.source_root, roots.runtime_root, roots.execution_namespace_root) == roots


def test_manifest_root_vector_is_frozen_independently() -> None:
    roots = derive_capture_namespace_roots_v1(_manifest())
    assert roots.source_root.hex() == "11eed677cf8f66d28e60026a72ca92b4acf20920cdf941bd026caec4ff4b2b8a"
    assert roots.runtime_root.hex() == "6e9f7e65d76c0c01327d1b4ab29db8a2369e9be2f3df55b83f93c33ca5d9b7fa"
    assert roots.execution_namespace_root.hex() == "392b39d614425d28583d4a4d290db9b282be81d7b36a98a647d12b898d9c031d"


def test_root_object_is_explicitly_zero_authority() -> None:
    roots = derive_capture_namespace_roots_v1(_manifest())
    assert roots.authority is AUTHORITY is False
    assert roots.engine_wiring_authority is ENGINE_WIRING_AUTHORITY is False
    assert roots.upload_authority is UPLOAD_AUTHORITY is False
    assert roots.permit_authority is PERMIT_AUTHORITY is False
    assert roots.holdout_access_authority is HOLDOUT_ACCESS_AUTHORITY is False
    assert roots.agent_modification_authority is AGENT_MODIFICATION_AUTHORITY is False
    assert roots.calibration_upload_authority is CALIBRATION_UPLOAD_AUTHORITY is False
    assert roots.production_upload_authority is PRODUCTION_UPLOAD_AUTHORITY is False
    assert roots.sealed_holdout_access_authority is SEALED_HOLDOUT_ACCESS_AUTHORITY is False


@pytest.mark.parametrize("path", ["", "/bin/collector", "bin//collector", "bin/./collector", "bin/../collector", "bin\\collector", "bad\x00path"])
def test_relative_paths_fail_closed(path: str) -> None:
    manifest = _manifest()
    manifest[4][0][0] = path
    _error(CAPTURE_NAMESPACE_PATH_INVALID, validate_capture_namespace_manifest_v1, manifest)


def test_working_and_primary_paths_follow_the_same_rules() -> None:
    for index in (1, 2):
        manifest = _manifest()
        manifest[index] = "../escape"
        _error(CAPTURE_NAMESPACE_PATH_INVALID, validate_capture_namespace_manifest_v1, manifest)


def test_rows_must_be_strictly_sorted_by_utf8_bytes_and_unique() -> None:
    manifest = _manifest()
    manifest[4][0], manifest[4][1] = manifest[4][1], manifest[4][0]
    _error(CAPTURE_NAMESPACE_ORDER_INVALID, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[4][1][0] = manifest[4][0][0]
    _error(CAPTURE_NAMESPACE_ORDER_INVALID, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[4].append(["z/\u00e9", [RUNTIME_DEPENDENCY], 0o444, 1, _digest("unicode")])
    manifest[4].append(["z/z", [RUNTIME_DEPENDENCY], 0o444, 1, _digest("ascii")])
    _error(CAPTURE_NAMESPACE_ORDER_INVALID, validate_capture_namespace_manifest_v1, manifest)


@pytest.mark.parametrize("roles", [[], [PRIMARY_SOURCE, PRIMARY_SOURCE], [SOURCE_INPUT, PRIMARY_SOURCE], [9]])
def test_roles_must_be_nonempty_increasing_unique_and_known(roles: list[int]) -> None:
    manifest = _manifest()
    manifest[4][3][1] = roles
    _error(CAPTURE_NAMESPACE_ROLE_INVALID if roles in ([], [9]) else CAPTURE_NAMESPACE_ORDER_INVALID, validate_capture_namespace_manifest_v1, manifest)


def test_collector_and_primary_presence_and_binding_are_required() -> None:
    manifest = _manifest()
    manifest[4][0][1] = [RUNTIME_DEPENDENCY]
    manifest[4][0][2] = 0o444
    _error(CAPTURE_NAMESPACE_ROLE_INVALID, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[4][3][1] = [SOURCE_INPUT]
    _error(CAPTURE_NAMESPACE_ROLE_INVALID, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[2] = "src/other.cpp"
    _error(CAPTURE_NAMESPACE_SCHEMA_INVALID, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[4][3][0] = "src/Other.cpp"
    _error(CAPTURE_NAMESPACE_SCHEMA_INVALID, validate_capture_namespace_manifest_v1, manifest)


def test_modes_lengths_and_digests_are_exact() -> None:
    manifest = _manifest()
    manifest[4][0][2] = 0o444
    _error(CAPTURE_NAMESPACE_MODE_INVALID, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[4][1][2] = 0o555
    _error(CAPTURE_NAMESPACE_MODE_INVALID, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[4][0][3] = -1
    _error(CAPTURE_NAMESPACE_INVALID_TYPE, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[4][0][4] = b"too short"
    _error(CAPTURE_NAMESPACE_DIGEST_INVALID, validate_capture_namespace_manifest_v1, manifest)


def test_manifest_and_path_profile_are_arrays_only() -> None:
    _error(CAPTURE_NAMESPACE_INVALID_TYPE, validate_capture_namespace_manifest_v1, tuple(_manifest()))

    manifest = _manifest()
    manifest[3] = {"not": "an array"}
    _error(CAPTURE_NAMESPACE_INVALID_TYPE, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[3] = [True]
    _error(CAPTURE_NAMESPACE_INVALID_TYPE, validate_capture_namespace_manifest_v1, manifest)


def test_schema_and_row_width_are_exact() -> None:
    manifest = _manifest()
    manifest[0] = True
    _error(CAPTURE_NAMESPACE_INVALID_TYPE, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[0] = 2
    _error(CAPTURE_NAMESPACE_SCHEMA_INVALID, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest.pop()
    _error(CAPTURE_NAMESPACE_SCHEMA_INVALID, validate_capture_namespace_manifest_v1, manifest)

    manifest = _manifest()
    manifest[4][0].pop()
    _error(CAPTURE_NAMESPACE_SCHEMA_INVALID, validate_capture_namespace_manifest_v1, manifest)


def test_root_claims_fail_closed_on_wrong_width_or_any_mismatch() -> None:
    manifest = _manifest()
    roots = derive_capture_namespace_roots_v1(manifest)
    _error(CAPTURE_NAMESPACE_DIGEST_INVALID, validate_capture_namespace_roots_v1, manifest, b"short", roots.runtime_root, roots.execution_namespace_root)
    _error(CAPTURE_NAMESPACE_ROOT_MISMATCH, validate_capture_namespace_roots_v1, manifest, bytes(32), roots.runtime_root, roots.execution_namespace_root)
    _error(CAPTURE_NAMESPACE_ROOT_MISMATCH, validate_capture_namespace_roots_v1, manifest, roots.source_root, bytes(32), roots.execution_namespace_root)
    _error(CAPTURE_NAMESPACE_ROOT_MISMATCH, validate_capture_namespace_roots_v1, manifest, roots.source_root, roots.runtime_root, bytes(32))


def test_roots_change_when_the_committed_manifest_changes() -> None:
    manifest = _manifest()
    roots = derive_capture_namespace_roots_v1(manifest)

    source_changed = deepcopy(manifest)
    source_changed[4][3][4] = _digest("primary-changed")
    changed = derive_capture_namespace_roots_v1(source_changed)
    assert changed.source_root != roots.source_root
    assert changed.runtime_root == roots.runtime_root
    assert changed.execution_namespace_root != roots.execution_namespace_root

    runtime_changed = deepcopy(manifest)
    runtime_changed[4][0][4] = _digest("collector-changed")
    changed = derive_capture_namespace_roots_v1(runtime_changed)
    assert changed.source_root == roots.source_root
    assert changed.runtime_root != roots.runtime_root
    assert changed.execution_namespace_root != roots.execution_namespace_root


def test_decoder_rejects_noncanonical_or_non_array_cbor() -> None:
    manifest = _manifest()
    canonical = eir_canonical_cbor_encode(manifest)
    assert decode_capture_namespace_manifest_v1(canonical) == manifest
    _error(CAPTURE_NAMESPACE_CANONICAL_ENCODING, decode_capture_namespace_manifest_v1, canonical + b"\x00")
    _error(CAPTURE_NAMESPACE_CANONICAL_ENCODING, decode_capture_namespace_manifest_v1, eir_canonical_cbor_encode(1))
