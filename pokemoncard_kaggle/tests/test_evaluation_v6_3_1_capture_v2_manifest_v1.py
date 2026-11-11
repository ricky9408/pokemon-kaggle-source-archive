from copy import deepcopy
from hashlib import sha256

import pytest

from evaluation_v6_3_1.capture_v2_manifest_v1 import (
    AGENT_MODIFICATION_AUTHORITY,
    AUTHORITY,
    CALIBRATION_UPLOAD_AUTHORITY,
    CAPTURE_V2_MANIFEST_DERIVATION_FAILED,
    CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_CBOR,
    CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256,
    CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1,
    PATH_PROFILE_V2_CBOR,
    HOLDOUT_ACCESS_AUTHORITY,
    PERMIT_AUTHORITY,
    PRODUCTION_UPLOAD_AUTHORITY,
    SEALED_HOLDOUT_ACCESS_AUTHORITY,
    UPLOAD_AUTHORITY,
    CaptureV2ManifestDerivationError,
    derive_input_manifests_v1,
)
from evaluation_v6_3_1.eir_prebinding import (
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
)
from tests.test_evaluation_v6_3_1_capture_v2_assembler import _bridge_value


def _digest(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _receipt_events(raw: bytes) -> list[list[object]]:
    events: list[list[object]] = []
    offset = 0
    while offset < len(raw):
        assert raw[offset : offset + 8] == b"V631CR01"
        length = int.from_bytes(raw[offset + 8 : offset + 16], "big")
        start = offset + 16
        events.append(eir_canonical_cbor_decode(raw[start : start + length]))
        offset = start + length
    return events


def _kwargs() -> dict[str, object]:
    bridge = _bridge_value()
    final = _receipt_events(bridge[5][0])[-1][4]
    return {
        "argv_grammar_version": bridge[2][3],
        "argv_grammar_sha256": bridge[2][4],
        "working_directory_relative_path": bridge[3][0],
        "primary_source_relative_path": bridge[3][1],
        "path_profile": eir_canonical_cbor_decode(bridge[3][2]),
        "public_file_rows": deepcopy(bridge[3][3]),
        "namespace_identity_rows": deepcopy(bridge[3][4]),
        "driver_argv": deepcopy(final[5]),
        "cc1_argv": deepcopy(final[6]),
        "actual_open_rows": deepcopy(bridge[5][1]),
    }


def _error(**kwargs: object) -> CaptureV2ManifestDerivationError:
    with pytest.raises(CaptureV2ManifestDerivationError) as raised:
        derive_input_manifests_v1(**kwargs)
    assert raised.value.code == CAPTURE_V2_MANIFEST_DERIVATION_FAILED
    return raised.value


def test_frozen_grammar_bytes_and_hash_are_stable_and_zero_authority() -> None:
    assert len(CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_CBOR) == 1262
    assert CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256.hex() == (
        "085029058792fedadb7441d733321e961255bf65598b2b54a439cb426db54160"
    )
    assert AUTHORITY is False
    assert UPLOAD_AUTHORITY is False
    assert PERMIT_AUTHORITY is False
    assert HOLDOUT_ACCESS_AUTHORITY is False
    assert AGENT_MODIFICATION_AUTHORITY is False
    assert CALIBRATION_UPLOAD_AUTHORITY is False
    assert PRODUCTION_UPLOAD_AUTHORITY is False
    assert SEALED_HOLDOUT_ACCESS_AUTHORITY is False


def test_exact_pinned_profile_derives_driver_and_cc1_manifests() -> None:
    kwargs = _kwargs()
    derived = derive_input_manifests_v1(**kwargs)
    expected = [["src/Export.cpp", 23, _digest("primary")]]
    assert derived.driver_manifest == [kwargs["driver_argv"], expected]
    assert derived.cc1_manifest == [kwargs["cc1_argv"], expected]
    assert derived.path_profile.namespace_root == "/"
    assert derived.path_profile.working_directory_relative_path == "work"


def test_relative_paths_split_resource_form_and_duplicate_search_reference() -> None:
    kwargs = _kwargs()
    driver = kwargs["driver_argv"]
    cc1 = kwargs["cc1_argv"]
    assert isinstance(driver, list) and isinstance(cc1, list)
    driver[driver.index("/src/Export.cpp")] = "../src/Export.cpp"
    cc1[cc1.index("/src/Export.cpp")] = "../src/Export.cpp"
    resource = driver.index("-resource-dir=/lib/clang/16")
    driver[resource : resource + 1] = ["-resource-dir", "/lib/clang/16"]
    include = driver.index("-I")
    driver[include:include] = ["-I", "/src"]
    derived = derive_input_manifests_v1(**kwargs)
    assert derived.driver_manifest[1] == [["src/Export.cpp", 23, _digest("primary")]]


def test_repeated_opens_collapse_and_implicit_headers_enter_each_phase() -> None:
    kwargs = _kwargs()
    kwargs["public_file_rows"].append(
        ["src/Implicit.h", [3], 0o444, 29, _digest("implicit")]
    )
    kwargs["namespace_identity_rows"].append(
        ["src/Implicit.h", [0, 105], 205, 1, 0o444, 29, _digest("implicit")]
    )
    kwargs["actual_open_rows"] = [
        [0, 1, "src/Export.cpp", 0, 101, 201, 0o444, 23, _digest("primary")],
        [1, 1, "src/Implicit.h", 0, 105, 205, 0o444, 29, _digest("implicit")],
        [2, 1, "src/Export.cpp", 0, 101, 201, 0o444, 23, _digest("primary")],
        [3, 2, "src/Export.cpp", 0, 101, 201, 0o444, 23, _digest("primary")],
        [4, 2, "src/Implicit.h", 0, 105, 205, 0o444, 29, _digest("implicit")],
        [5, 2, "src/Implicit.h", 0, 105, 205, 0o444, 29, _digest("implicit")],
    ]
    derived = derive_input_manifests_v1(**kwargs)
    expected = sorted(
        [
            ["src/Export.cpp", 23, _digest("primary")],
            ["src/Implicit.h", 29, _digest("implicit")],
        ],
        key=eir_canonical_cbor_encode,
    )
    assert derived.driver_manifest[1] == expected
    assert derived.cc1_manifest[1] == expected


@pytest.mark.parametrize(
    "mutate",
    [
        lambda k: k["driver_argv"].append("-unknown-option"),
        lambda k: k["driver_argv"].append("@args.rsp"),
        lambda k: k["cc1_argv"].__setitem__(2, "arm64-unknown-linux-gnu"),
        lambda k: k["cc1_argv"].__setitem__(0, "clang"),
        lambda k: k["cc1_argv"].__setitem__(k["cc1_argv"].index("Export.cpp"), "Other.cpp"),
        lambda k: k["driver_argv"].__setitem__(k["driver_argv"].index("/src"), "/outside"),
        lambda k: k.__setitem__("working_directory_relative_path", "other"),
        lambda k: k["path_profile"].__setitem__(2, "/outside/bin"),
        lambda k: k.__setitem__("argv_grammar_version", 2),
        lambda k: k.__setitem__("argv_grammar_sha256", bytes(32)),
    ],
)
def test_unknown_ambiguous_or_out_of_profile_argv_fails_closed(mutate) -> None:
    kwargs = _kwargs()
    mutate(kwargs)
    _error(**kwargs)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda k: k["namespace_identity_rows"].pop(),
        lambda k: k["namespace_identity_rows"].__setitem__(
            1, deepcopy(k["namespace_identity_rows"][0])
        ),
        lambda k: (
            k["namespace_identity_rows"][1].__setitem__(
                1, deepcopy(k["namespace_identity_rows"][0][1])
            ),
            k["namespace_identity_rows"][1].__setitem__(
                2, k["namespace_identity_rows"][0][2]
            ),
        ),
        lambda k: k["namespace_identity_rows"][4].__setitem__(3, 2),
        lambda k: k["namespace_identity_rows"][4].__setitem__(4, 0o555),
        lambda k: k["namespace_identity_rows"][4].__setitem__(6, bytes(32)),
        lambda k: k["actual_open_rows"][0].__setitem__(4, 999),
        lambda k: k["actual_open_rows"][0].__setitem__(5, 999),
        lambda k: k["actual_open_rows"][0].__setitem__(6, 0o555),
        lambda k: k["actual_open_rows"][0].__setitem__(1, 2),
        lambda k: k["actual_open_rows"].pop(0),
    ],
)
def test_namespace_identity_and_phase_custody_fail_closed(mutate) -> None:
    kwargs = _kwargs()
    mutate(kwargs)
    _error(**kwargs)


def test_path_normalization_cannot_escape_namespace_root() -> None:
    kwargs = _kwargs()
    driver = kwargs["driver_argv"]
    assert isinstance(driver, list)
    driver[driver.index("/src/Export.cpp")] = "../../../etc/passwd"
    _error(**kwargs)


def test_grammar_artifact_round_trip_is_byte_identical() -> None:
    value = eir_canonical_cbor_decode(CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_CBOR)
    assert eir_canonical_cbor_encode(value) == CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_CBOR
    assert CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1 == 1
