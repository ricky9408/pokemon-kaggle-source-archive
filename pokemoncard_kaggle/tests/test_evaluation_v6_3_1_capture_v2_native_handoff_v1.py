import inspect
from hashlib import sha256

import pytest

import evaluation_v6_3_1.capture_v2_native_handoff_v1 as handoff_module
from evaluation_v6_3_1.capture_v2_manifest_v1 import (
    CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256,
    CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1,
    PATH_PROFILE_V2_CBOR,
)
from evaluation_v6_3_1.capture_v2_native_handoff_v1 import (
    MAXIMUM_GNU_BUILD_ID_DESCRIPTOR_BYTES_V1,
    MAXIMUM_PROFILE_BUILD_LABEL_BYTES_V1,
    NATIVE_PRELAUNCH_HANDOFF_V1,
    NativePrelaunchHandoffError,
    RawPrelaunchInput,
    _decode_handoff,
    _prepare_session,
    _raw_cbor_encode,
    decode_raw_prelaunch_request_v1,
    derive_direct_in_process_clang_collector_launch_contract_v2,
    encode_raw_prelaunch_request_v1,
    produce_capture_v2_via_native,
    to_native_prelaunch_handoff,
    to_raw_prelaunch_request_v1,
)
from evaluation_v6_3_1.capture_v2_prelaunch_expectations import (
    PrelaunchExpectationsError,
    VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2,
    VALIDATED_PRELAUNCH_EXPECTATIONS_VERSION_V2,
    ValidatedPrelaunchExpectationsV2,
    freeze_validated_prelaunch_expectations_v2,
)
from evaluation_v6_3_1.eir_prebinding import eir_canonical_cbor_decode, eir_canonical_cbor_encode
from tests.test_evaluation_v6_3_1_capture_v2_assembler import (
    DEFAULT_BUILD_LABEL,
    _diagnostic_profile_and_transport,
)


def _public_rows() -> bytes:
    return eir_canonical_cbor_encode(
        [
            ["bin/collector", [1], 0o555, 17, sha256(b"collector").digest()],
            ["lib/ld-linux-x86-64.so.2", [6], 0o444, 19, bytes.fromhex("02" * 32)],
            ["lib/libc.so.6", [8], 0o444, 25, bytes.fromhex("03" * 32)],
            ["lib/libclang-cpp.so.16", [7, 8], 0o444, 21, sha256(b"clang").digest()],
            ["src/Export.cpp", [2, 3], 0o444, 23, bytes.fromhex("05" * 32)],
        ]
    )


def _harness() -> tuple[tuple[int, bytes, bytes], ...]:
    return (
        (41, bytes.fromhex("11" * 32), b"entry"),
        (43, bytes.fromhex("12" * 32), b""),
        (41, bytes.fromhex("13" * 32), b"supervisor"),
    )


def _inner_driver_argv() -> tuple[str, ...]:
    return (
        "/bin/clang-tool",
        "-std=c++20",
        "-fsyntax-only",
        "-nostdinc",
        "-I",
        "/src",
        "/src/Export.cpp",
        "-resource-dir=/lib/clang/16",
        "--no-default-config",
    )


def _raw_input(**changes) -> RawPrelaunchInput:
    profile_cbor, _ = _diagnostic_profile_and_transport()
    values = dict(
        collector_profile_build_label_text=DEFAULT_BUILD_LABEL,
        expected_collector_gnu_build_id_descriptor_bytes=b"\x00\xab",
        collector_profile_cbor_bytes=profile_cbor,
        path_profile_cbor_bytes=PATH_PROFILE_V2_CBOR,
        working_directory_relative_path="work",
        primary_source_relative_path="src/Export.cpp",
        argv_grammar_version=CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1,
        argv_grammar_sha256=CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256,
        public_file_rows_cbor_bytes=_public_rows(),
        requested_argv=_inner_driver_argv(),
        harness_expectations=_harness(),
    )
    values.update(changes)
    return RawPrelaunchInput(**values)


def _artifact(raw_input: RawPrelaunchInput | None = None) -> ValidatedPrelaunchExpectationsV2:
    value = _raw_input() if raw_input is None else raw_input
    return freeze_validated_prelaunch_expectations_v2(
        collector_profile_build_label_text=value.collector_profile_build_label_text,
        expected_collector_gnu_build_id_descriptor_bytes=value.expected_collector_gnu_build_id_descriptor_bytes,
        collector_profile_cbor_bytes=value.collector_profile_cbor_bytes,
        argv_grammar_version=value.argv_grammar_version,
        argv_grammar_sha256=value.argv_grammar_sha256,
        path_profile_cbor_bytes=value.path_profile_cbor_bytes,
        working_directory_relative_path=value.working_directory_relative_path,
        primary_source_relative_path=value.primary_source_relative_path,
        public_file_rows_cbor_bytes=value.public_file_rows_cbor_bytes,
        requested_argv=value.requested_argv,
        harness_expectations=[list(item) for item in value.harness_expectations],
    )


def _raw_bytes(raw_input: RawPrelaunchInput | None = None) -> bytes:
    return encode_raw_prelaunch_request_v1(_artifact(raw_input))


def test_raw_request_is_exactly_thirteen_root_free_fields() -> None:
    decoded = decode_raw_prelaunch_request_v1(_raw_bytes())
    assert len(decoded.as_value()) == 13
    assert decoded.as_value()[:2] == [631302, 1]
    assert decoded.as_value()[2:4] == [DEFAULT_BUILD_LABEL, b"\x00\xab"]
    assert decoded.as_value()[7:10] == [PATH_PROFILE_V2_CBOR, "work", "src/Export.cpp"]
    assert decoded.as_value()[11] == list(_inner_driver_argv())
    assert decoded.as_value()[12][1][2] == b""
    assert b"validated_prelaunch_expectations_root" not in decoded.canonical_cbor_bytes


def test_embedded_artifacts_are_byte_strings_and_preserve_original_bytes() -> None:
    raw = _raw_bytes()
    value = eir_canonical_cbor_decode(raw)
    assert all(type(value[index]) is bytes for index in (3, 4, 6, 7, 10))
    assert value[4] == _raw_input().collector_profile_cbor_bytes
    assert value[7] == PATH_PROFILE_V2_CBOR
    assert value[10] == _public_rows()
    assert decode_raw_prelaunch_request_v1(raw).canonical_cbor_bytes == raw


def test_handoff_is_exact_four_fields_and_has_one_outer_root() -> None:
    artifact = _artifact()
    root = artifact.validated_prelaunch_expectations_root
    raw = encode_raw_prelaunch_request_v1(artifact)
    encoded = to_native_prelaunch_handoff(artifact)
    value = _decode_handoff(encoded)
    assert len(value) == 4
    assert value[:2] == [631302, NATIVE_PRELAUNCH_HANDOFF_V1]
    assert value[2] == root
    assert value[3] == raw
    assert decode_raw_prelaunch_request_v1(value[3]).as_value()[0:2] == [631302, 1]


def test_prepare_session_cross_checks_all_raw_fields_against_one_opaque_artifact() -> None:
    session = _prepare_session(_raw_input())
    assert session.raw_request.canonical_cbor_bytes == session.handoff_bytes[-len(session.raw_request.canonical_cbor_bytes) :]
    assert session.expectations.public_file_rows_cbor_bytes == _public_rows()
    assert session.expectations.requested_argv == _inner_driver_argv()
    assert session.expectations.harness_expectations == _harness()
    assert session.expectations_root == _decode_handoff(session.handoff_bytes)[2]
    assert to_native_prelaunch_handoff(session.expectations) == session.handoff_bytes
    launch = derive_direct_in_process_clang_collector_launch_contract_v2(
        session.expectations
    )
    assert launch.executable_path == "/bin/collector"
    assert launch.absolute_primary == "/src/Export.cpp"
    assert launch.capture_context_cbor_bytes == eir_canonical_cbor_encode(
        [1, "src/Export.cpp", [2, "/src", "/work", "/bin"]]
    )
    assert launch.capture_context_hex == launch.capture_context_cbor_bytes.hex()
    assert launch.capture_context_hex == launch.capture_context_hex.lower()
    assert launch.argv == (
        "/bin/collector",
        "--protocol=631302",
        "--level=2",
        "--primary-source=/src/Export.cpp",
        "--capture-context-v1-cbor-hex=" + launch.capture_context_hex,
        "--",
        *_inner_driver_argv(),
    )


def test_retired_argv0_substitution_launch_surface_is_absent() -> None:
    assert not hasattr(handoff_module, "derive_direct_collector_launch_argv_v1")
    assert not hasattr(handoff_module, "_derive_direct_collector_launch_argv_from_raw")


def test_launch_preserves_every_inner_driver_token_after_separator() -> None:
    requested = (
        "/bin/clang-tool",
        "-std=c++20",
        "-fsyntax-only",
        "-nostdinc",
        "-I",
        "/src",
        "/src/Export.cpp",
        "-resource-dir",
        "/lib/clang/16",
        "--no-default-config",
    )
    launch = derive_direct_in_process_clang_collector_launch_contract_v2(
        _artifact(_raw_input(requested_argv=requested))
    )
    separator = launch.argv.index("--")
    assert launch.argv[separator + 1 :] == requested
    assert launch.argv[separator + 1] == "/bin/clang-tool"


@pytest.mark.parametrize("mutation", ["missing_libclang", "fake_clang_tool", "wrong_libclang_sha", "wrong_collector_sha"])
def test_freeze_rejects_wrong_runtime_topology_or_profile_projection(
    mutation: str,
) -> None:
    rows = eir_canonical_cbor_decode(_public_rows())
    if mutation == "missing_libclang":
        rows.pop(3)
    elif mutation == "fake_clang_tool":
        rows.insert(
            0,
            ["bin/clang-tool", [7], 0o444, 1, sha256(b"fake").digest()],
        )
    elif mutation == "wrong_libclang_sha":
        rows[3][4] = sha256(b"wrong-clang").digest()
    elif mutation == "wrong_collector_sha":
        rows[0][4] = sha256(b"wrong-collector").digest()
    with pytest.raises(PrelaunchExpectationsError):
        _artifact(
            _raw_input(
                public_file_rows_cbor_bytes=eir_canonical_cbor_encode(rows)
            )
        )


def test_prepare_session_freezes_artifact_before_deriving_raw_wire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    original_freeze = handoff_module.freeze_validated_prelaunch_expectations_v2
    original_request = handoff_module._request_from_expectations

    def freeze_first(**kwargs):
        events.append("artifact")
        return original_freeze(**kwargs)

    def request_second(artifact):
        events.append("raw-request")
        return original_request(artifact)

    monkeypatch.setattr(
        handoff_module,
        "freeze_validated_prelaunch_expectations_v2",
        freeze_first,
    )
    monkeypatch.setattr(
        handoff_module,
        "_request_from_expectations",
        request_second,
    )
    session = handoff_module._prepare_session(_raw_input())
    assert events == ["artifact", "raw-request"]
    assert _decode_handoff(session.handoff_bytes)[3] == (
        session.raw_request.canonical_cbor_bytes
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop(),
        lambda value: value.append(b"unexpected"),
        lambda value: value.__setitem__(2, "other-label"),
        lambda value: value.__setitem__(3, b""),
        lambda value: value.__setitem__(5, 2),
        lambda value: value.__setitem__(6, bytes(32)),
    lambda value: value.__setitem__(8, "other"),
    lambda value: value.__setitem__(9, "src/Other.cpp"),
        lambda value: value.__setitem__(11, ["/bin/clang-tool"]),
        lambda value: value[12].__setitem__(1, [0, bytes.fromhex("12" * 32), b""]),
    ],
)
def test_raw_request_mutations_fail_closed(mutate) -> None:
    value = eir_canonical_cbor_decode(_raw_bytes())
    mutate(value)
    with pytest.raises(NativePrelaunchHandoffError):
        decode_raw_prelaunch_request_v1(_raw_cbor_encode(value))


def test_raw_request_rejects_noncanonical_and_trailing_embedded_bytes() -> None:
    raw = _raw_bytes()
    value = eir_canonical_cbor_decode(raw)
    value[4] += b"\x00"
    with pytest.raises(NativePrelaunchHandoffError):
        decode_raw_prelaunch_request_v1(_raw_cbor_encode(value))
    with pytest.raises(NativePrelaunchHandoffError):
        decode_raw_prelaunch_request_v1(raw + b"\x00")


@pytest.mark.parametrize(
    "encoded",
    [
        b"\xa0",  # map
        b"\x20",  # negative integer
        b"\xf5",  # boolean
        b"\x9f\x01\xff",  # indefinite-length array
        b"\x81\x18\x01",  # non-shortest uint encoding
    ],
)
def test_raw_codec_rejects_forbidden_or_noncanonical_cbor(encoded: bytes) -> None:
    with pytest.raises(ValueError):
        handoff_module._raw_cbor_decode(encoded)


@pytest.mark.parametrize("field", ["collector_profile_build_label_text", "public_file_rows_cbor_bytes", "requested_argv", "harness_expectations"])
def test_opaque_expectations_mismatch_fails_closed(field: str) -> None:
    from evaluation_v6_3_1.capture_v2_native_handoff_v1 import _cross_check_request
    from evaluation_v6_3_1.capture_v2_prelaunch_expectations import freeze_validated_prelaunch_expectations_v2

    source = _raw_input()
    artifact = freeze_validated_prelaunch_expectations_v2(
        collector_profile_build_label_text=source.collector_profile_build_label_text,
        expected_collector_gnu_build_id_descriptor_bytes=source.expected_collector_gnu_build_id_descriptor_bytes,
        collector_profile_cbor_bytes=source.collector_profile_cbor_bytes,
        argv_grammar_version=source.argv_grammar_version,
        argv_grammar_sha256=source.argv_grammar_sha256,
        path_profile_cbor_bytes=source.path_profile_cbor_bytes,
        working_directory_relative_path=source.working_directory_relative_path,
        primary_source_relative_path=source.primary_source_relative_path,
        public_file_rows_cbor_bytes=source.public_file_rows_cbor_bytes,
        requested_argv=source.requested_argv,
        harness_expectations=source.harness_expectations,
    )
    value = eir_canonical_cbor_decode(_raw_bytes())
    if field == "collector_profile_build_label_text":
        value[2] = "different-label"
        profile = eir_canonical_cbor_decode(value[4])
        profile[1] = value[2]
        value[4] = eir_canonical_cbor_encode(profile)
    elif field == "public_file_rows_cbor_bytes":
        rows = eir_canonical_cbor_decode(value[10])
        rows[0][3] += 1
        value[10] = eir_canonical_cbor_encode(rows)
    elif field == "requested_argv":
        value[11] = [
            "/bin/clang-tool",
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "-I",
            "/src",
            "/src/Export.cpp",
            "-resource-dir",
            "/lib/clang/16",
            "--no-default-config",
        ]
    else:
        value[12][0][0] += 1
    mutated = decode_raw_prelaunch_request_v1(_raw_cbor_encode(value))
    with pytest.raises(NativePrelaunchHandoffError):
        _cross_check_request(artifact, mutated)


def test_outer_handoff_rejects_noncanonical_shape_and_root_in_raw_request() -> None:
    raw = _raw_bytes()
    root = bytes(32)
    value = [631302, NATIVE_PRELAUNCH_HANDOFF_V1, root, raw]
    value[3] = _raw_cbor_encode(eir_canonical_cbor_decode(raw) + [root])
    with pytest.raises(NativePrelaunchHandoffError):
        _decode_handoff(_raw_cbor_encode(value))
    canonical = _raw_cbor_encode([631302, NATIVE_PRELAUNCH_HANDOFF_V1, root, raw])
    assert canonical[0] == 0x84
    with pytest.raises(NativePrelaunchHandoffError):
        _decode_handoff(b"\x98\x04" + canonical[1:])


@pytest.mark.parametrize(
    "changes",
    [
        {"collector_profile_build_label_text": ""},
        {"collector_profile_build_label_text": "x" * (MAXIMUM_PROFILE_BUILD_LABEL_BYTES_V1 + 1)},
        {"collector_profile_build_label_text": "\u00e9"},
        {"expected_collector_gnu_build_id_descriptor_bytes": b""},
        {"expected_collector_gnu_build_id_descriptor_bytes": b"x" * (MAXIMUM_GNU_BUILD_ID_DESCRIPTOR_BYTES_V1 + 1)},
        {"working_directory_relative_path": "work/"},
        {"primary_source_relative_path": "src/../Export.cpp"},
    ],
)
def test_frozen_scalar_limits_and_path_grammar_fail_closed(changes) -> None:
    with pytest.raises((NativePrelaunchHandoffError, PrelaunchExpectationsError)):
        _raw_bytes(_raw_input(**changes))


def test_requested_argv_is_exact_inner_driver_argv() -> None:
    decoded = decode_raw_prelaunch_request_v1(_raw_bytes())
    assert decoded.requested_argv == _inner_driver_argv()
    with pytest.raises((NativePrelaunchHandoffError, PrelaunchExpectationsError)):
        _raw_bytes(_raw_input(requested_argv=("/bin/clang-tool",)))
    with pytest.raises((NativePrelaunchHandoffError, PrelaunchExpectationsError)):
        _raw_bytes(_raw_input(requested_argv=("/bin/collector", *_inner_driver_argv()[1:])))


def test_v2_root_binds_every_raw_semantic_leaf_and_is_not_v1_compatible() -> None:
    artifact = _artifact()
    value = eir_canonical_cbor_decode(artifact.canonical_cbor_bytes)
    assert value[:3] == [631302, VALIDATED_PRELAUNCH_EXPECTATIONS_VERSION_V2, 1]
    assert len(value) == 14
    assert artifact.validated_prelaunch_expectations_root == sha256(
        VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2 + artifact.canonical_cbor_bytes
    ).digest()
    for index in (6, 7, 11, 12, 13):
        mutated = eir_canonical_cbor_decode(artifact.canonical_cbor_bytes)
        if index == 6:
            mutated[index] += 1
        elif index == 7:
            mutated[index] = bytes(32)
        elif index == 11:
            rows = eir_canonical_cbor_decode(mutated[index])
            rows[0][3] += 1
            mutated[index] = eir_canonical_cbor_encode(rows)
        elif index == 12:
            mutated[index] = ["/bin/clang-tool"]
        else:
            mutated[index][0][0] += 1
        assert sha256(
            VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2
            + eir_canonical_cbor_encode(mutated)
        ).digest() != artifact.validated_prelaunch_expectations_root


def test_raw_serializer_accepts_only_frozen_v2_and_leaves_are_immutable() -> None:
    artifact = _artifact()
    assert encode_raw_prelaunch_request_v1(artifact) == to_raw_prelaunch_request_v1(
        artifact
    ).canonical_cbor_bytes
    with pytest.raises((AttributeError, TypeError)):
        artifact.requested_argv = ("/bin/clang-tool",)  # type: ignore[misc]
    with pytest.raises((NativePrelaunchHandoffError, TypeError)):
        encode_raw_prelaunch_request_v1(  # type: ignore[arg-type]
            to_raw_prelaunch_request_v1(artifact)
        )
    assert not hasattr(handoff_module, "encode_native_prelaunch_handoff_v1")


@pytest.mark.parametrize("member", ["canonical", "root"])
def test_tampered_v2_artifact_cannot_derive_a_raw_request(member: str) -> None:
    artifact = _artifact()
    if member == "canonical":
        object.__setattr__(
            artifact,
            "_ValidatedPrelaunchExpectationsV2__canonical_cbor_bytes",
            artifact.canonical_cbor_bytes + b"\x00",
        )
    else:
        object.__setattr__(
            artifact,
            "_ValidatedPrelaunchExpectationsV2__root",
            bytes(32),
        )
    with pytest.raises(NativePrelaunchHandoffError):
        to_raw_prelaunch_request_v1(artifact)


def test_production_transport_is_called_only_after_exact_python_validation() -> None:
    calls: list[bytes] = []

    def transport(handoff: bytes) -> bytes:
        calls.append(handoff)
        raise AssertionError("fixture transport has no valid native bridge")

    with pytest.raises(NativePrelaunchHandoffError) as raised:
        handoff_module._produce_capture_v2_with_test_transport(_raw_input(), transport)
    assert calls
    assert "native transport failed closed" in str(raised.value)


def test_production_path_names_the_authoritative_assembler_entry() -> None:
    assert hasattr(handoff_module, "assemble_capture_v2_production")
    assert "assemble_capture_v2_production" in inspect.getsource(
        handoff_module._produce_capture_v2_with_test_transport
    )
    public_source = inspect.getsource(handoff_module.produce_capture_v2_via_native)
    assert "_produce_capture_v2_with_test_transport" not in public_source
    assert "loaded-image custody is not implemented" in public_source


def test_public_production_path_is_unconditionally_fail_closed() -> None:
    with pytest.raises(NativePrelaunchHandoffError) as raised:
        produce_capture_v2_via_native(_raw_input())
    assert "loaded-image custody is not implemented" in str(raised.value)
    assert list(inspect.signature(produce_capture_v2_via_native).parameters) == [
        "raw_prelaunch_input"
    ]
