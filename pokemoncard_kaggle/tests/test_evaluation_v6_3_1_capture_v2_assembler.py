from copy import deepcopy
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path

import pytest

import evaluation_v6_3_1.m0_diagnostic_census as census_module
from evaluation_v6_3_1.capture_namespace_v1 import (
    CLANG_CPP_IMPLEMENTATION,
    COLLECTOR_EXECUTABLE,
    ELF_INTERPRETER,
    PRIMARY_SOURCE,
    RUNTIME_DEPENDENCY,
    SOURCE_INPUT,
)
from evaluation_v6_3_1.capture_v2 import (
    decode_raw_collector_capture_v2,
    validate_raw_collector_capture_v2,
)
from evaluation_v6_3_1.capture_v2_assembler import (
    AGENT_MODIFICATION_AUTHORITY,
    AUTHORITY,
    CALIBRATION_UPLOAD_AUTHORITY,
    CAPTURE_V2_ASSEMBLY_FAILED,
    HOLDOUT_ACCESS_AUTHORITY,
    NATIVE_PRODUCTION_EVIDENCE_BRIDGE_V3,
    PERMIT_AUTHORITY,
    PRODUCTION_UPLOAD_AUTHORITY,
    SEALED_HOLDOUT_ACCESS_AUTHORITY,
    UPLOAD_AUTHORITY,
    CaptureV2AssemblyError,
    _bridge_decode,
    _bridge_encode,
    assemble_production_capture_v2,
)
from evaluation_v6_3_1.capture_v2_manifest_v1 import (
    CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256,
    CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1,
    PATH_PROFILE_V2_CBOR,
)
from evaluation_v6_3_1.capture_v2_prelaunch_expectations import (
    PRELAUNCH_EXPECTATIONS_INVALID,
    VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2,
    VALIDATED_PRELAUNCH_EXPECTATIONS_VERSION_V2,
    PrelaunchExpectationsError,
    ValidatedPrelaunchExpectationsV2,
    freeze_validated_prelaunch_expectations_v2,
)
from evaluation_v6_3_1.eir_prebinding import (
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
)
from evaluation_v6_3_1.m0_diagnostic_census import (
    CANONICALIZER_BUNDLE_DOMAIN,
    CANONICALIZER_ENTRY_MODULE_PATH,
    CANONICALIZER_WORKER_ENTRY_PATH,
    canonicalize_diagnostic_census_v1,
)
from evaluation_v6_3_1.m0_diagnostic_primitives import (
    canonical_cbor_decode as diagnostic_cbor_decode,
    canonical_cbor_encode as diagnostic_cbor_encode,
)


ROOT = Path(__file__).resolve().parents[1]
PINNED_INTERPRETER_SHA256 = bytes.fromhex(
    "6d972cf21be56fe3c947ab6ba257ff8d08c342dd2714442986791bd9a6dfabfe"
)
DEFAULT_BUILD_LABEL = "636f6c6c6563746f722d6275696c64"


def _digest(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _frozen_descriptors() -> list[list[object]]:
    artifact = json.loads(
        (
            ROOT
            / "strategy/evaluation_v6_3_1_entropy_static_closure_sourcebound_20260721.json"
        ).read_text(encoding="utf-8")
    )
    targets = artifact["details"]["compiler_derived_dispatch_proof"]["targets"]
    return [[row["index"], row["name"], row["qual_type"]] for row in targets]


@lru_cache(maxsize=1)
def _diagnostic_profile_and_transport() -> tuple[bytes, bytes]:
    paths = [
        "evaluation_v6_3_1/__init__.py",
        CANONICALIZER_ENTRY_MODULE_PATH,
        "evaluation_v6_3_1/m0_diagnostic_primitives.py",
        CANONICALIZER_WORKER_ENTRY_PATH,
    ]
    files: list[list[object]] = []
    for relative in sorted(paths, key=lambda value: value.encode("utf-8")):
        raw = (ROOT / relative).read_bytes()
        files.append([relative, len(raw), sha256(raw).digest()])
    manifest: list[object] = [1, CANONICALIZER_ENTRY_MODULE_PATH, files]
    bundle_root = sha256(
        diagnostic_cbor_encode(
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
    profile: list[object] = [
        _digest("collector"),
        DEFAULT_BUILD_LABEL,
        _digest("clang"),
        16,
        1,
        execution_profile,
        bundle_root,
        manifest,
    ]
    descriptors = _frozen_descriptors()
    raw_transport = diagnostic_cbor_encode(
        [
            descriptors,
            [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]],
            [],
            [],
            [],
        ]
    )
    return diagnostic_cbor_encode(profile), raw_transport


def _profile_with_label(label: str) -> bytes:
    profile_cbor, _ = _diagnostic_profile_and_transport()
    profile = diagnostic_cbor_decode(profile_cbor)
    profile[1] = label
    return diagnostic_cbor_encode(profile)


def _prelaunch_public_rows() -> bytes:
    return eir_canonical_cbor_encode(
        [
            ["bin/collector", [COLLECTOR_EXECUTABLE], 0o555, 17, _digest("collector")],
            ["lib/ld-linux-x86-64.so.2", [ELF_INTERPRETER], 0o444, 19, _digest("loader")],
            ["lib/libc.so.6", [RUNTIME_DEPENDENCY], 0o444, 25, _digest("libc")],
            ["lib/libclang-cpp.so.16", [CLANG_CPP_IMPLEMENTATION, RUNTIME_DEPENDENCY], 0o444, 21, _digest("clang")],
            ["src/Export.cpp", [PRIMARY_SOURCE, SOURCE_INPUT], 0o444, 23, _digest("primary")],
        ]
    )


def _prelaunch_driver_argv() -> tuple[str, ...]:
    return (
        "/bin/clang-tool", "-std=c++20", "-fsyntax-only", "-nostdinc",
        "-I", "/src", "/src/Export.cpp", "-resource-dir=/lib/clang/16",
        "--no-default-config",
    )


def _prelaunch_harness() -> tuple[tuple[int, bytes, bytes], ...]:
    return (
        (41, _digest("entry"), b"\x00\x01\x00\xff"),
        (43, _digest("interpreter"), b"\x00\x80\xaa"),
        (41, _digest("entry"), b"\x00\x01\x00\xff"),
    )


def _expectations(
    *,
    label: str = DEFAULT_BUILD_LABEL,
    descriptor: bytes = b"\x00\xab",
    profile_cbor: bytes | None = None,
) -> ValidatedPrelaunchExpectationsV2:
    return freeze_validated_prelaunch_expectations_v2(
        collector_profile_build_label_text=label,
        expected_collector_gnu_build_id_descriptor_bytes=descriptor,
        collector_profile_cbor_bytes=(
            _profile_with_label(label) if profile_cbor is None else profile_cbor
        ),
        argv_grammar_version=CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1,
        argv_grammar_sha256=CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256,
        path_profile_cbor_bytes=PATH_PROFILE_V2_CBOR,
        working_directory_relative_path="work",
        primary_source_relative_path="src/Export.cpp",
        public_file_rows_cbor_bytes=_prelaunch_public_rows(),
        requested_argv=_prelaunch_driver_argv(),
        harness_expectations=_prelaunch_harness(),
    )


def _template_unproven_transport() -> bytes:
    descriptors = _frozen_descriptors()
    pattern = [
        [2, [0]],
        "FunctionDecl",
        ["/v631302/src/Export.cpp", 10, 11],
    ]
    specialization = [
        [2, [1]],
        "FunctionDecl",
        ["/v631302/src/Export.cpp", 20, 21],
    ]
    definition = [
        "FunctionDecl",
        descriptors[0][1],
        descriptors[0][2],
        1,
        [0],
        "/v631302/src/Export.cpp",
        20,
        21,
    ]
    source_rows = [
        [
            pattern,
            [0, 0, 0, 1, 0, [0, 1, [], [1, [specialization]], []]],
            2,
            [],
        ],
        [specialization, [0, 0, 0, 0, 1, []], 1, []],
    ]
    invocation_rows = [[[2, specialization, definition], []]]
    return diagnostic_cbor_encode(
        [
            descriptors,
            [[2, 1, 1, 0], [0, 0, 0, 0], [0, 0, 0, 0]],
            source_rows,
            [],
            invocation_rows,
        ]
    )


def _frame(event: list[object]) -> bytes:
    payload = eir_canonical_cbor_encode(event)
    return b"V631CR01" + len(payload).to_bytes(8, "big") + payload


def _receipt_with_driver(raw: bytes, driver: list[str]) -> bytes:
    frames: list[bytes] = []
    offset = 0
    while offset < len(raw):
        assert raw[offset : offset + 8] == b"V631CR01"
        length = int.from_bytes(raw[offset + 8 : offset + 16], "big")
        payload_start = offset + 16
        payload_end = payload_start + length
        event = eir_canonical_cbor_decode(raw[payload_start:payload_end])
        assert isinstance(event, list) and len(event) == 5
        if event[3] == 3:
            event[4] = list(driver)
        elif event[3] == 5:
            assert isinstance(event[4], list) and len(event[4]) == 8
            event[4][5] = list(driver)
        frames.append(_frame(event))
        offset = payload_end
    assert offset == len(raw)
    return b"".join(frames)


def _bridge_value(
    expectations: ValidatedPrelaunchExpectationsV2 | None = None,
) -> list[object]:
    if expectations is None:
        expectations = _expectations()
    path_profile = [2, "/src", "/work", "/bin"]
    file_rows = [
        ["bin/collector", [COLLECTOR_EXECUTABLE], 0o555, 17, _digest("collector")],
        ["lib/ld-linux-x86-64.so.2", [ELF_INTERPRETER], 0o444, 19, _digest("loader")],
        ["lib/libc.so.6", [RUNTIME_DEPENDENCY], 0o444, 25, _digest("libc")],
        [
            "lib/libclang-cpp.so.16",
            [CLANG_CPP_IMPLEMENTATION, RUNTIME_DEPENDENCY],
            0o444,
            21,
            _digest("clang"),
        ],
        ["src/Export.cpp", [PRIMARY_SOURCE, SOURCE_INPUT], 0o444, 23, _digest("primary")],
    ]
    namespace_identities = [
        ["bin/collector", [0, 100], 200, 1, 0o555, 17, _digest("collector")],
        ["lib/ld-linux-x86-64.so.2", [0, 102], 202, 1, 0o444, 19, _digest("loader")],
        ["lib/libc.so.6", [0, 103], 203, 1, 0o444, 25, _digest("libc")],
        ["lib/libclang-cpp.so.16", [0, 104], 204, 1, 0o444, 21, _digest("clang")],
        ["src/Export.cpp", [0, 101], 201, 1, 0o444, 23, _digest("primary")],
    ]
    actual_opens = [
        [0, 1, "src/Export.cpp", 0, 101, 201, 0o444, 23, _digest("primary")],
        [1, 2, "src/Export.cpp", 0, 101, 201, 0o444, 23, _digest("primary")],
    ]
    driver = [
        "/bin/clang-tool",
        "-std=c++20",
        "-fsyntax-only",
        "-nostdinc",
        "-I",
        "/src",
        "/src/Export.cpp",
        "-resource-dir=/lib/clang/16",
        "--no-default-config",
    ]
    cc1 = [
        "-cc1",
        "-triple",
        "x86_64-unknown-linux-gnu",
        "-fsyntax-only",
        "-disable-free",
        "-clear-ast-before-backend",
        "-disable-llvm-verifier",
        "-discard-value-names",
        "-main-file-name",
        "Export.cpp",
        "-mrelocation-model",
        "pic",
        "-pic-level",
        "2",
        "-pic-is-pie",
        "-mframe-pointer=all",
        "-fmath-errno",
        "-ffp-contract=on",
        "-fno-rounding-math",
        "-mconstructor-aliases",
        "-funwind-tables=2",
        "-target-cpu",
        "x86-64",
        "-tune-cpu",
        "generic",
        "-mllvm",
        "-treat-scalable-fixed-error-as-warning",
        "-debugger-tuning=gdb",
        "-fcoverage-compilation-dir=/",
        "-nostdsysteminc",
        "-nobuiltininc",
        "-resource-dir",
        "/lib/clang/16",
        "-I",
        "/src",
        "-std=c++20",
        "-fdeprecated-macro",
        "-fdebug-compilation-dir=/",
        "-ferror-limit",
        "19",
        "-fgnuc-version=4.2.1",
        "-fno-implicit-modules",
        "-fcxx-exceptions",
        "-fexceptions",
        "-faddrsig",
        "-D__GCC_HAVE_DWARF2_CFI_ASM=1",
        "-x",
        "c++",
        "/src/Export.cpp",
    ]
    receipt_binding = [3, 501, 601]
    transitions = [
        [0, 0, 1],
        [1, 1, 3],
        [2, 2, 4],
        [3, 3, 6],
        [4, 4, 7],
        [5, 5, 8],
        [6, 6, 9],
    ]
    final = [
        631302,
        1,
        receipt_binding,
        "src/Export.cpp",
        path_profile,
        driver,
        cc1,
        transitions,
    ]
    receipt_events = [
        [631302, 1, 0, 1, receipt_binding],
        [631302, 1, 1, 2, [0, 0]],
        [631302, 1, 2, 3, driver],
        [631302, 1, 3, 2, [1, 1]],
        [631302, 1, 4, 2, [2, 2]],
        [631302, 1, 5, 4, cc1],
        [631302, 1, 6, 2, [3, 3]],
        [631302, 1, 7, 2, [4, 4]],
        [631302, 1, 8, 2, [5, 5]],
        [631302, 1, 9, 2, [6, 6]],
        [631302, 1, 10, 5, final],
    ]
    receipt_stream = b"".join(_frame(event) for event in receipt_events)
    collector_object = [
        "bin/collector",
        b"",
        17,
        _digest("collector"),
        b"\x00\xab",
    ]
    loader = [
        "lib/ld-linux-x86-64.so.2",
        b"",
        19,
        _digest("loader"),
        b"loader-build",
    ]
    libc = [
        "lib/libc.so.6",
        b"libc.so.6",
        25,
        _digest("libc"),
        b"libc-build",
    ]
    primary = [
        "lib/libclang-cpp.so.16",
        b"libclang-cpp.so.16",
        21,
        _digest("clang"),
        b"clang-build",
    ]
    runtime_objects = [collector_object, loader, libc, primary]
    runtime_observations = [
        [0, 1, 0, 100, 200, 0, 0, 0],
        [1, 2, 1, 102, 202, 0, 19, 5],
        [2, 2, 2, 103, 203, 0, 25, 5],
        [3, 3, 3, 104, 204, 0, 21, 5],
    ]

    _, raw_collector_bytes = _diagnostic_profile_and_transport()
    harness_facts = [
        [41, _digest("entry"), b"\x00\x01\x00\xff"],
        [43, _digest("interpreter"), b"\x00\x80\xaa"],
        [41, _digest("entry"), b"\x00\x01\x00\xff"],
    ]
    capture_context = eir_canonical_cbor_encode(
        [1, "src/Export.cpp", path_profile]
    )
    collector_launch_argv = [
        "/bin/collector",
        "--protocol=631302",
        "--level=2",
        "--primary-source=/src/Export.cpp",
        "--capture-context-v1-cbor-hex=" + capture_context.hex(),
        "--",
        *expectations.requested_argv,
    ]

    return [
        631302,
        NATIVE_PRODUCTION_EVIDENCE_BRIDGE_V3,
        [
            expectations.collector_profile_build_label_text,
            expectations.expected_collector_gnu_build_id_descriptor_bytes,
            expectations.collector_profile_cbor_bytes,
            expectations.argv_grammar_version,
            expectations.argv_grammar_sha256,
        ],
        [
            "work",
            "src/Export.cpp",
            eir_canonical_cbor_encode(path_profile),
            file_rows,
            namespace_identities,
        ],
        [
            [collector_launch_argv, "work", 17, _digest("collector")],
            expectations.validated_prelaunch_expectations_root,
        ],
        [receipt_stream, actual_opens],
        [primary, loader, runtime_objects, runtime_observations],
        [raw_collector_bytes],
        harness_facts,
        [0, b""],
    ]


def _bridge(
    expectations: ValidatedPrelaunchExpectationsV2 | None = None,
) -> bytes:
    return _bridge_encode(_bridge_value(expectations))


def _error(
    raw: bytes,
    expectations: ValidatedPrelaunchExpectationsV2 | None = None,
) -> CaptureV2AssemblyError:
    if expectations is None:
        expectations = _expectations()
    with pytest.raises(CaptureV2AssemblyError) as raised:
        assemble_production_capture_v2(raw, expectations)
    assert raised.value.code == CAPTURE_V2_ASSEMBLY_FAILED
    return raised.value


def test_assembler_constructs_complete_capture_and_revalidates_every_root() -> None:
    encoded = assemble_production_capture_v2(_bridge(), _expectations())
    capture = eir_canonical_cbor_decode(encoded)
    roots = validate_raw_collector_capture_v2(capture)

    assert capture[0:2] == [631302, 2]
    assert capture[2] == [17, _digest("collector"), "636f6c6c6563746f722d6275696c64"]
    assert capture[3][0][0] == 1
    assert capture[4][3] == []
    assert capture[5][1] == _bridge_value()[5][0]
    assert all(len(row) == 8 for row in capture[5][6])
    assert capture[6][0:2] == [2, 16]
    assert capture[6][4][0][4] == b"\x00\xab"
    assert capture[7] == [
        len(_bridge_value()[7][0]),
        sha256(_bridge_value()[7][0]).digest(),
    ]
    assert capture[8][0][2] == b"\x00\x01\x00\xff".hex()
    assert capture[8][1][2] == b"\x00\x80\xaa".hex()
    assert bytes.fromhex(capture[8][0][2]) == b"\x00\x01\x00\xff"
    assert bytes.fromhex(capture[8][1][2]) == b"\x00\x80\xaa"
    assert capture[9] == [0, 0, sha256(b"").digest()]
    assert roots == decode_raw_collector_capture_v2(encoded)
    assert eir_canonical_cbor_encode(capture) == encoded


def test_assembler_and_bridge_are_permanently_zero_authority() -> None:
    assemble_production_capture_v2(_bridge(), _expectations())
    assert AUTHORITY is False
    assert UPLOAD_AUTHORITY is False
    assert PERMIT_AUTHORITY is False
    assert HOLDOUT_ACCESS_AUTHORITY is False
    assert AGENT_MODIFICATION_AUTHORITY is False
    assert CALIBRATION_UPLOAD_AUTHORITY is False
    assert PRODUCTION_UPLOAD_AUTHORITY is False
    assert SEALED_HOLDOUT_ACCESS_AUTHORITY is False


def test_prelaunch_artifact_has_the_exact_frozen_value_and_root() -> None:
    artifact = _expectations()
    value = [
        631302,
        VALIDATED_PRELAUNCH_EXPECTATIONS_VERSION_V2,
        1,
        artifact.collector_profile_build_label_text,
        artifact.expected_collector_gnu_build_id_descriptor_bytes,
        artifact.collector_profile_cbor_bytes,
        artifact.argv_grammar_version,
        artifact.argv_grammar_sha256,
        artifact.path_profile_cbor_bytes,
        artifact.working_directory_relative_path,
        artifact.primary_source_relative_path,
        artifact.public_file_rows_cbor_bytes,
        list(artifact.requested_argv),
        [list(item) for item in artifact.harness_expectations],
    ]
    assert artifact.canonical_cbor_bytes == eir_canonical_cbor_encode(value)
    assert artifact.validated_prelaunch_expectations_root == sha256(
        VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2
        + eir_canonical_cbor_encode(value)
    ).digest()


def test_prelaunch_artifact_is_opaque_immutable_and_not_bridge_constructible() -> None:
    artifact = _expectations()
    with pytest.raises(AttributeError):
        artifact.argv_grammar_version = 2  # type: ignore[misc]
    with pytest.raises(TypeError):
        ValidatedPrelaunchExpectationsV2(  # type: ignore[arg-type]
            None,
            artifact.canonical_cbor_bytes,
            artifact.validated_prelaunch_expectations_root,
            eir_canonical_cbor_decode(artifact.canonical_cbor_bytes),
        )
    assert not hasattr(ValidatedPrelaunchExpectationsV2, "from_bridge")
    assert not hasattr(ValidatedPrelaunchExpectationsV2, "from_untrusted_bytes")
    assert not hasattr(
        ValidatedPrelaunchExpectationsV2, "from_observed_descriptor"
    )


def test_legacy_v1_expectations_construction_surface_is_deleted() -> None:
    import evaluation_v6_3_1.capture_v2_prelaunch_expectations as prelaunch

    assert not hasattr(prelaunch, "ValidatedPrelaunchExpectationsV1")
    assert not hasattr(prelaunch, "freeze_validated_prelaunch_expectations_v1")
    assert not hasattr(prelaunch, "VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V1")


@pytest.mark.parametrize(
    "label",
    [
        pytest.param("A", id="one-byte"),
        pytest.param("A" * 1_048_576, id="maximum"),
    ],
)
def test_prelaunch_label_accepts_the_exact_frozen_ascii_boundaries(
    label: str,
) -> None:
    artifact = _expectations(label=label)
    assert artifact.collector_profile_build_label_text == label


@pytest.mark.parametrize(
    "label",
    [
        pytest.param("", id="empty"),
        pytest.param("\x01", id="ascii-control"),
        pytest.param("A\x00B", id="nul"),
        pytest.param("\x80", id="non-ascii"),
        pytest.param("A" * 1_048_577, id="oversized"),
    ],
)
def test_prelaunch_label_rejects_values_outside_the_frozen_ascii_grammar(
    label: str,
) -> None:
    with pytest.raises(PrelaunchExpectationsError) as raised:
        _expectations(
            label=label,
            profile_cbor=_diagnostic_profile_and_transport()[0],
        )
    assert raised.value.code == PRELAUNCH_EXPECTATIONS_INVALID


def test_prelaunch_descriptor_requires_one_to_65535_bytes() -> None:
    with pytest.raises(PrelaunchExpectationsError):
        _expectations(descriptor=b"")
    maximum = b"x" * 65_535
    assert (
        _expectations(descriptor=maximum)
        .expected_collector_gnu_build_id_descriptor_bytes
        == maximum
    )
    with pytest.raises(PrelaunchExpectationsError):
        _expectations(descriptor=b"x" * 65_536)


def test_one_argument_assembler_overload_is_retired() -> None:
    with pytest.raises(TypeError):
        assemble_production_capture_v2(_bridge())  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "artifact",
    [
        None,
        b"artifact",
        [],
        {},
        b"\x00\xab",
    ],
)
def test_assembler_requires_the_opaque_prelaunch_artifact(artifact) -> None:
    with pytest.raises(CaptureV2AssemblyError) as raised:
        assemble_production_capture_v2(_bridge(), artifact)
    assert raised.value.code == CAPTURE_V2_ASSEMBLY_FAILED


def test_tampered_artifact_and_bridge_roots_fail_closed() -> None:
    artifact = _expectations()
    raw = _bridge(artifact)
    object.__setattr__(
        artifact,
        "_ValidatedPrelaunchExpectationsV2__canonical_cbor_bytes",
        artifact.canonical_cbor_bytes + b"\x00",
    )
    _error(raw, artifact)

    artifact = _expectations()
    raw = _bridge(artifact)
    object.__setattr__(
        artifact,
        "_ValidatedPrelaunchExpectationsV2__root",
        bytes(32),
    )
    _error(raw, artifact)

    artifact = _expectations()
    value = _bridge_value(artifact)
    value[4][1] = bytes(32)
    _error(_bridge_encode(value), artifact)


def test_matching_root_does_not_replace_collector_field_checks() -> None:
    artifact = _expectations()

    value = _bridge_value(artifact)
    value[2][1] = b"\x00\xac"
    value[6][2][0][4] = b"\x00\xac"
    _error(_bridge_encode(value), artifact)

    value = _bridge_value(artifact)
    alternate_label = "alternate-build"
    value[2][0] = alternate_label
    value[2][2] = _profile_with_label(alternate_label)
    _error(_bridge_encode(value), artifact)

    value = _bridge_value(artifact)
    value[2][3] = 2
    _error(_bridge_encode(value), artifact)

    value = _bridge_value(artifact)
    value[2][4] = bytes(32)
    _error(_bridge_encode(value), artifact)


def test_prelaunch_artifact_cross_binds_every_native_commitment_surface() -> None:
    artifact = _expectations()

    value = _bridge_value(artifact)
    value[4][0][0][2] = "--level=3"
    assert "exact derived collector launch" in str(
        _error(_bridge_encode(value), artifact)
    )

    value = _bridge_value(artifact)
    value[3][3][4][4] = _digest("different-primary")
    assert "public file rows" in str(_error(_bridge_encode(value), artifact))

    value = _bridge_value(artifact)
    value[8][0][2] = b"different-entry-build"
    value[8][2][2] = b"different-entry-build"
    assert "harness facts" in str(_error(_bridge_encode(value), artifact))

    value = _bridge_value(artifact)
    different_driver = list(artifact.requested_argv)
    different_driver[5] = "/bin"
    value[5][0] = _receipt_with_driver(value[5][0], different_driver)
    assert "receipt driver argv" in str(_error(_bridge_encode(value), artifact))


def test_bridge_round_trip_is_byte_identical() -> None:
    raw = _bridge()
    assert _bridge_encode(_bridge_decode(raw)) == raw


def test_private_bridge_v3_requires_exact_collector_facts_width_and_version() -> None:
    value = _bridge_value()
    assert value[1] == NATIVE_PRODUCTION_EVIDENCE_BRIDGE_V3
    assemble_production_capture_v2(_bridge_encode(value), _expectations())

    value = _bridge_value()
    value[1] = 2
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[2].pop(1)
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[2].append(b"unexpected")
    _error(_bridge_encode(value))


def test_v2_shape_is_rejected_without_descriptor_inference() -> None:
    value = _bridge_value()
    value[1] = 2
    value[2] = [value[2][0], value[2][2], value[2][3], value[2][4]]
    _error(_bridge_encode(value))


def test_pre_erratum_execution_block_and_stdout_shapes_are_rejected() -> None:
    value = _bridge_value()
    value[4] = value[4][0]
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[7] = value[7][0]
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[7] = []
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[7].append(b"duplicate")
    _error(_bridge_encode(value))


def test_execution_cwd_is_exactly_the_manifest_relative_path() -> None:
    value = _bridge_value()
    assert value[4][0][1] == "work"
    assemble_production_capture_v2(_bridge_encode(value), _expectations())

    value = _bridge_value()
    value[4][0][1] = "/work"
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[4][0][1] = "other-work"
    _error(_bridge_encode(value))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[2].__setitem__(0, b"636f6c6c6563746f722d6275696c64"),
        lambda b: b[2].__setitem__(1, "00ab"),
        lambda b: b[2].__setitem__(0, ""),
        lambda b: b[2].__setitem__(1, b"x" * 65_536),
    ],
)
def test_v3_collector_identity_types_and_bounds_fail_closed(mutate) -> None:
    value = _bridge_value()
    mutate(value)
    _error(_bridge_encode(value))


def test_v3_null_descriptor_is_rejected_on_the_raw_wire() -> None:
    raw = _bridge().replace(b"\x42\x00\xab", b"\xf6", 1)
    _error(raw)


def test_profile_label_must_equal_v3_label_and_descriptor_is_not_hex_encoded() -> None:
    value = _bridge_value()
    profile = diagnostic_cbor_decode(value[2][2])
    profile[1] = "other-label"
    value[2][2] = diagnostic_cbor_encode(profile)
    _error(_bridge_encode(value))

    value = _bridge_value()
    profile = diagnostic_cbor_decode(value[2][2])
    profile[1] = "636f6c6c6563746f722d6275696c65"
    value[2][2] = diagnostic_cbor_encode(profile)
    _error(_bridge_encode(value))

    encoded = assemble_production_capture_v2(_bridge(), _expectations())
    capture = eir_canonical_cbor_decode(encoded)
    assert capture[2][2] == _bridge_value()[2][0]
    assert capture[2][2] != "00ab"
    assert capture[6][4][0][4] == b"\x00\xab"
    assert capture[6][4][0][4] != b"30306162"


def test_empty_descriptor_is_rejected_before_native_observation() -> None:
    with pytest.raises(PrelaunchExpectationsError):
        _expectations(descriptor=b"")

    value = _bridge_value()
    value[2][1] = b""
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[6][2][0][4] = b""
    _error(_bridge_encode(value))

    value = _bridge_value()
    del value[2][1]
    _error(_bridge_encode(value))


def test_observed_descriptor_must_match_the_identified_collector_runtime_row() -> None:
    value = _bridge_value()
    value[2][1] = b"\x00\xac"
    _error(_bridge_encode(value))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda runtime: runtime.__setitem__(0, []),
        lambda runtime: runtime.__setitem__(0, 7),
        lambda runtime: runtime.__setitem__(0, ["lib/x.so", b"x", 1]),
        lambda runtime: runtime.__setitem__(1, ["lib/x.so", b"x", 1]),
        lambda runtime: runtime[2].__setitem__(0, []),
        lambda runtime: runtime[2].__setitem__(0, ["bin/collector", b"", 17, b"short", b"id"]),
        lambda runtime: runtime[3].__setitem__(0, []),
        lambda runtime: runtime[3].__setitem__(0, [0, 1, 0, 100, 200, 0, 0, "bad"]),
    ],
)
def test_malformed_nested_runtime_facts_raise_typed_assembly_error(mutate) -> None:
    value = _bridge_value()
    mutate(value[6])
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[6][2][0][4] = b"\x00\xac"
    _error(_bridge_encode(value))


def test_native_bridge_requires_frozen_direct_dynamic_elf_topology() -> None:
    value = _bridge_value()
    value[8][2] = [47, _digest("other-supervisor"), b"other-build"]
    error = _error(_bridge_encode(value))
    assert "capture entry and supervisor" in str(error)

    value = _bridge_value()
    value[8][1] = deepcopy(value[8][0])
    error = _error(_bridge_encode(value))
    assert "interpreter must be a distinct observed ELF" in str(error)


def test_private_harness_build_id_rejects_text_and_oversized_bytes() -> None:
    value = _bridge_value()
    value[8][0][2] = "000100ff"
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[8][0][2] = b"x" * 65_536
    _error(_bridge_encode(value))


def test_private_empty_harness_build_id_fails_at_public_nonempty_boundary() -> None:
    value = _bridge_value()
    value[8][0][2] = b""
    _error(_bridge_encode(value))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xa0",
        b"\x01",
        b"\x9f\xff",
        b"\x81\xf4",
    ],
)
def test_non_arrays_only_bridge_forms_fail_closed(raw: bytes) -> None:
    _error(raw)


def test_noncanonical_truncated_and_trailing_bridge_bytes_fail_closed() -> None:
    raw = _bridge()
    _error(b"\x98\x0a" + raw[1:])
    _error(raw[:-1])
    _error(raw + b"\x00")


def test_test_only_open_receipt_slice_shape_cannot_enter_production() -> None:
    value = _bridge_value()
    test_only_shape = [value[5][1], [], value[5][0], value[7][0]]
    _error(_bridge_encode(test_only_shape))


def test_extra_root_or_pass_fields_have_no_bridge_slot() -> None:
    value = _bridge_value()
    value.append(bytes(32))
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[6].append(True)
    with pytest.raises(CaptureV2AssemblyError):
        _bridge_encode(value)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[3][3].append(deepcopy(b[3][3][0])),
        lambda b: b[3][3][0].__setitem__(4, bytes(32)),
        lambda b: b[3][4][0].__setitem__(6, bytes(32)),
        lambda b: (
            b[3][4][1].__setitem__(1, deepcopy(b[3][4][0][1])),
            b[3][4][1].__setitem__(2, b[3][4][0][2]),
        ),
        lambda b: b[4][0].__setitem__(1, 99),
        lambda b: b[4][0].__setitem__(2, bytes(32)),
        lambda b: b[4][0][0].__setitem__(0, "other/collector"),
        lambda b: b[5][1][0].__setitem__(6, 0o555),
        lambda b: b[5][1][0].__setitem__(8, bytes(32)),
        lambda b: b[5][1][1].__setitem__(1, 1),
        lambda b: b[5][1][0].__setitem__(2, "missing.cpp"),
        lambda b: b[6][2][1].__setitem__(3, bytes(32)),
        lambda b: b[6][3][1].__setitem__(2, 99),
        lambda b: b[6][3][0].__setitem__(3, 999),
        lambda b: b[6][3][0].__setitem__(4, 999),
        lambda b: b[7].__setitem__(0, b"\x01"),
        lambda b: b[8][0].__setitem__(2, ""),
        lambda b: b[9].__setitem__(0, 1),
        lambda b: b[9].__setitem__(1, b"stderr"),
    ],
)
def test_cross_section_and_leaf_mutations_fail_closed(mutate) -> None:
    value = _bridge_value()
    mutate(value)
    _error(_bridge_encode(value))


def test_receipt_mutation_fails_before_capture_emission() -> None:
    value = _bridge_value()
    value[5][0] = b"X" + value[5][0][1:]
    _error(_bridge_encode(value))


def test_canonical_but_semantically_invalid_collector_stdout_fails_closed() -> None:
    value = _bridge_value()
    value[7][0] = _bridge_encode([0])
    _error(_bridge_encode(value))


@pytest.mark.parametrize("field", [0, 1, 2])
def test_prelaunch_profile_must_match_sealed_collector(field: int) -> None:
    value = _bridge_value()
    profile = diagnostic_cbor_decode(value[2][2])
    profile[field] = "other-build" if field == 1 else bytes(32)
    value[2][2] = diagnostic_cbor_encode(profile)
    _error(_bridge_encode(value))


def test_prelaunch_profile_bytes_must_be_exact_canonical_cbor() -> None:
    value = _bridge_value()
    value[2][2] += b"\x00"
    _error(_bridge_encode(value))


def test_template_unproven_transport_is_captured_but_remains_status_two(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = _bridge_value()
    raw_transport = _template_unproven_transport()
    value[7][0] = raw_transport
    encoded = assemble_production_capture_v2(
        _bridge_encode(value), _expectations()
    )
    capture = eir_canonical_cbor_decode(encoded)
    assert capture[7] == [len(raw_transport), sha256(raw_transport).digest()]

    monkeypatch.setitem(
        census_module.__dict__,
        "V631302_BOUND_COLLECTOR_PROFILE_CBOR",
        value[2][2],
    )
    result = diagnostic_cbor_decode(
        canonicalize_diagnostic_census_v1(raw_transport)
    )
    assert result == [631302, 1, 2, b""]
    assert PRODUCTION_UPLOAD_AUTHORITY is False


def test_path_profile_must_be_exact_canonical_cbor() -> None:
    value = _bridge_value()
    value[3][2] += b"\x00"
    _error(_bridge_encode(value))


def test_bridge_rejects_retired_manifests_and_wrong_grammar_pin() -> None:
    value = _bridge_value()
    value[5].insert(1, [["src/Export.cpp", 23, _digest("primary")]])
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[2][3] = 2
    _error(_bridge_encode(value))

    value = _bridge_value()
    value[2][4] = bytes(32)
    _error(_bridge_encode(value))


def test_manifests_are_derived_from_exact_phase_opens() -> None:
    capture = eir_canonical_cbor_decode(
        assemble_production_capture_v2(_bridge(), _expectations())
    )
    expected = [["src/Export.cpp", 23, _digest("primary")]]
    assert capture[5][4][1] == expected
    assert capture[5][5][1] == expected

    value = _bridge_value()
    value[5][1][1][1] = 1
    _error(_bridge_encode(value))


def test_public_entrypoint_accepts_bytes_only() -> None:
    with pytest.raises(CaptureV2AssemblyError) as raised:
        assemble_production_capture_v2(
            _bridge_value(),  # type: ignore[arg-type]
            _expectations(),
        )
    assert raised.value.code == CAPTURE_V2_ASSEMBLY_FAILED
