from copy import deepcopy
from hashlib import sha256

import pytest

from evaluation_v6_3_1.capture_namespace_v1 import (
    CAPTURE_NAMESPACE_MANIFEST_V1,
    CLANG_CPP_IMPLEMENTATION,
    COLLECTOR_EXECUTABLE,
    ELF_INTERPRETER,
    PRIMARY_SOURCE,
    RUNTIME_DEPENDENCY,
    SOURCE_INPUT,
    derive_capture_namespace_roots_v1,
)
from evaluation_v6_3_1.capture_v2 import (
    AGENT_MODIFICATION_AUTHORITY,
    AUTHORITY,
    CALIBRATION_UPLOAD_AUTHORITY,
    ENGINE_WIRING_AUTHORITY,
    EXTERNAL_EVIDENCE_PREREQUISITES,
    HOLDOUT_ACCESS_AUTHORITY,
    M0_DIAGNOSTIC_INVENTORY_INCOMPLETE,
    PERMIT_AUTHORITY,
    PRODUCTION_UPLOAD_AUTHORITY,
    RAW_COLLECTOR_CAPTURE_MAX_BYTES_V1,
    SEALED_HOLDOUT_ACCESS_AUTHORITY,
    UPLOAD_AUTHORITY,
    decode_raw_collector_capture_v2,
    encode_raw_collector_capture_v2,
    raw_collector_capture_root_v2,
    validate_raw_collector_capture_v2,
)
from evaluation_v6_3_1.eir_prebinding import EIRPrebindingError, eir_canonical_cbor_encode
import evaluation_v6_3_1.capture_v2 as capture_v2


def _digest(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _manifest() -> list[object]:
    return [
        CAPTURE_NAMESPACE_MANIFEST_V1,
        "work",
        "src/Export.cpp",
        [2, "/src", "/work", "/bin"],
        [
            ["bin/collector", [COLLECTOR_EXECUTABLE], 0o555, 17, _digest("collector")],
            ["lib/ld-linux-x86-64.so.2", [ELF_INTERPRETER], 0o444, 19, _digest("loader")],
            ["lib/libc.so.6", [RUNTIME_DEPENDENCY], 0o444, 25, _digest("libc")],
            ["lib/libclang-cpp.so.16", [CLANG_CPP_IMPLEMENTATION, RUNTIME_DEPENDENCY], 0o444, 21, _digest("clang")],
            ["src/Export.cpp", [PRIMARY_SOURCE, SOURCE_INPUT], 0o444, 23, _digest("primary")],
        ],
    ]


def _root(domain: bytes, *fields: object) -> bytes:
    return sha256(eir_canonical_cbor_encode([domain, *fields])).digest()


def _frame(event: list[object]) -> bytes:
    payload = eir_canonical_cbor_encode(event)
    return b"V631CR01" + len(payload).to_bytes(8, "big") + payload


def _capture() -> list[object]:
    manifest = _manifest()
    namespace_roots = derive_capture_namespace_roots_v1(manifest)
    namespace = [
        manifest,
        namespace_roots.source_root,
        namespace_roots.runtime_root,
        namespace_roots.execution_namespace_root,
    ]
    collector = [17, _digest("collector"), "636f6c6c6563746f722d6275696c64"]
    actual_opens = [
        [0, 1, "src/Export.cpp", 0, 101, 201, 23, _digest("primary")],
        [1, 2, "src/Export.cpp", 0, 101, 201, 23, _digest("primary")],
    ]
    open_root = _root(b"V631302_ACTUAL_OPEN_TRACE_V1", 631302, 1, actual_opens)
    driver = ["clang-tool", "src/Export.cpp", "-fsyntax-only"]
    cc1 = ["-cc1", "src/Export.cpp", "-fsyntax-only"]
    binding = [3, 501, 601]
    transitions = [[0, 0, 1], [1, 1, 3], [2, 2, 4], [3, 3, 6], [4, 4, 7], [5, 5, 8], [6, 6, 9]]
    final = [631302, 1, binding, "src/Export.cpp", manifest[3], driver, cc1, transitions]
    events = [
        [631302, 1, 0, 1, binding],
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
    stream = b"".join(_frame(event) for event in events)
    driver_manifest = [driver, [["src/Export.cpp", 23, _digest("primary")]]]
    cc1_manifest = [cc1, [["src/Export.cpp", 23, _digest("primary")]]]
    invocation_root = _root(
        b"V631302_ACTUAL_COLLECTOR_INVOCATION_V2",
        631302,
        2,
        len(stream),
        sha256(stream).digest(),
        final,
        driver_manifest,
        cc1_manifest,
        open_root,
    )
    invocation = [2, stream, len(stream), sha256(stream).digest(), driver_manifest, cc1_manifest, actual_opens, invocation_root]
    execution = [1, "bin/collector", ["bin/collector"], [], 17, _digest("collector"), "work", open_root]
    collector_object = ["bin/collector", b"", 17, _digest("collector"), b"collector-build"]
    loader = ["lib/ld-linux-x86-64.so.2", b"", 19, _digest("loader"), b"loader-build"]
    libc = ["lib/libc.so.6", b"libc.so.6", 25, _digest("libc"), b"libc-build"]
    primary = ["lib/libclang-cpp.so.16", b"libclang-cpp.so.16", 21, _digest("clang"), b"clang-build"]
    objects = [collector_object, loader, libc, primary]
    observations = [
        [0, 1, 0, 101, 301, 0, 0, 0],
        [1, 2, 1, 102, 302, 0, 19, 5],
        [2, 2, 2, 103, 303, 0, 25, 5],
        [3, 3, 3, 104, 304, 0, 21, 5],
    ]
    observation_root = _root(b"V631302_CLANG_RUNTIME_OBSERVATION_V2", 631302, 2, objects, observations)
    closure_root = _root(
        b"V631302_CLANG_RUNTIME_CLOSURE_V2",
        631302,
        2,
        16,
        primary,
        loader,
        objects,
        observations,
        namespace_roots.runtime_root,
        observation_root,
    )
    runtime = [2, 16, primary, loader, objects, observations, namespace_roots.runtime_root, observation_root, closure_root]
    raw = [31, _digest("raw-census")]
    entry = [41, _digest("entry"), "000100ff"]
    interpreter = [43, _digest("interpreter"), "0080aa"]
    supervisor = [47, _digest("supervisor"), "000100ff"]
    harness_root = _root(b"V631302_CAPTURE_HARNESS_CLOSURE_V1", 631302, 1, entry, interpreter, supervisor)
    harness = [entry, interpreter, supervisor, harness_root]
    termination = [0, 0, sha256(b"").digest()]
    return [631302, 2, collector, namespace, execution, invocation, runtime, raw, harness, termination]


def _error(function, *args) -> None:
    with pytest.raises(EIRPrebindingError) as raised:
        function(*args)
    assert raised.value.code == M0_DIAGNOSTIC_INVENTORY_INCOMPLETE


def _events(capture: list[object]) -> list[list[object]]:
    stream = capture[5][1]
    events: list[list[object]] = []
    offset = 0
    while offset < len(stream):
        length = int.from_bytes(stream[offset + 8 : offset + 16], "big")
        start = offset + 16
        events.append(capture_v2.eir_canonical_cbor_decode(stream[start : start + length]))
        offset = start + length
    return events


def _replace_events(capture: list[object], events: list[list[object]]) -> None:
    capture[5][1] = b"".join(_frame(event) for event in events)


def _refresh_invocation(capture: list[object]) -> None:
    events = _events(capture)
    stream = capture[5][1]
    final = events[10][4]
    capture[5][2] = len(stream)
    capture[5][3] = sha256(stream).digest()
    capture[5][4][0] = events[2][4]
    capture[5][5][0] = events[5][4]
    open_root = _root(b"V631302_ACTUAL_OPEN_TRACE_V1", 631302, 1, capture[5][6])
    capture[5][7] = _root(
        b"V631302_ACTUAL_COLLECTOR_INVOCATION_V2",
        631302,
        2,
        len(stream),
        sha256(stream).digest(),
        final,
        capture[5][4],
        capture[5][5],
        open_root,
    )
    capture[4][7] = open_root


def _refresh_namespace_and_runtime_roots(capture: list[object]) -> None:
    namespace_roots = derive_capture_namespace_roots_v1(capture[3][0])
    capture[3][1] = namespace_roots.source_root
    capture[3][2] = namespace_roots.runtime_root
    capture[3][3] = namespace_roots.execution_namespace_root
    capture[6][6] = namespace_roots.runtime_root
    capture[6][8] = _root(
        b"V631302_CLANG_RUNTIME_CLOSURE_V2",
        631302,
        2,
        16,
        capture[6][2],
        capture[6][3],
        capture[6][4],
        capture[6][5],
        namespace_roots.runtime_root,
        capture[6][7],
    )


def test_complete_capture_round_trips_and_recomputes_every_root() -> None:
    capture = _capture()
    roots = validate_raw_collector_capture_v2(capture)
    encoded = encode_raw_collector_capture_v2(capture)
    decoded = decode_raw_collector_capture_v2(encoded)
    assert decoded == roots
    assert raw_collector_capture_root_v2(capture) == roots.raw_collector_capture_root
    assert roots.actual_open_trace_root == capture[4][7]
    assert roots.invocation_root == capture[5][7]
    assert roots.runtime_observation_root == capture[6][7]
    assert roots.clang_runtime_closure_root == capture[6][8]
    assert roots.capture_harness_closure_root == capture[8][3]
    assert all(len(root) == 32 for root in (
        roots.source_root,
        roots.runtime_root,
        roots.execution_namespace_root,
        roots.actual_open_trace_root,
        roots.invocation_root,
        roots.runtime_observation_root,
        roots.clang_runtime_closure_root,
        roots.capture_harness_closure_root,
        roots.raw_collector_capture_root,
    ))


def test_roots_are_byte_stable_and_permanently_zero_authority() -> None:
    capture = _capture()
    first = validate_raw_collector_capture_v2(capture)
    second = decode_raw_collector_capture_v2(encode_raw_collector_capture_v2(capture))
    assert first == second
    assert first.authority is AUTHORITY is False
    assert first.engine_wiring_authority is ENGINE_WIRING_AUTHORITY is False
    assert first.upload_authority is UPLOAD_AUTHORITY is False
    assert first.permit_authority is PERMIT_AUTHORITY is False
    assert first.holdout_access_authority is HOLDOUT_ACCESS_AUTHORITY is False
    assert first.agent_modification_authority is AGENT_MODIFICATION_AUTHORITY is False
    assert first.calibration_upload_authority is CALIBRATION_UPLOAD_AUTHORITY is False
    assert first.production_upload_authority is PRODUCTION_UPLOAD_AUTHORITY is False
    assert first.sealed_holdout_access_authority is SEALED_HOLDOUT_ACCESS_AUTHORITY is False
    assert "PTRACE_OR_EQUIVALENT_OPEN_TRACE_COMPLETENESS" in first.external_evidence_prerequisites
    assert "INDEPENDENT_DRIVER_CC1_MANIFEST_AND_PATH_RESOLUTION_DERIVATION" in first.external_evidence_prerequisites
    assert "CONCURRENT_DRAIN_LIMITS_AND_COMPLETE_CHANNEL_EOF" in first.external_evidence_prerequisites
    assert "ACTUAL_PT_INTERP_AND_ELF_METADATA_DERIVATION" in first.external_evidence_prerequisites
    assert first.external_evidence_prerequisites == EXTERNAL_EVIDENCE_PREREQUISITES


def test_component_build_ids_are_nonempty_text_not_runtime_elf_bytes() -> None:
    validate_raw_collector_capture_v2(_capture())

    capture = _capture()
    capture[2][2] = b"collector-build"
    _error(validate_raw_collector_capture_v2, capture)

    capture = _capture()
    capture[8][0][2] = ""
    _error(validate_raw_collector_capture_v2, capture)


@pytest.mark.parametrize(
    "build_id",
    [
        "000100FF",       # uppercase
        "000100f",        # odd number of nibbles
        "0x000100ff",     # prefix
        " 000100ff",      # leading whitespace
        "000100ff ",      # trailing whitespace
        "000100fg",       # non-hex character
        "０００１００ｆｆ",  # Unicode lookalikes
    ],
)
def test_public_harness_build_id_requires_canonical_lowercase_hex(build_id: str) -> None:
    capture = _capture()
    capture[8][0][2] = build_id
    _error(validate_raw_collector_capture_v2, capture)


def test_public_harness_build_id_accepts_zero_bytes_and_rejects_non_utf8() -> None:
    capture = _capture()
    assert capture[8][0][2] == "000100ff"
    assert bytes.fromhex(capture[8][0][2]) == b"\x00\x01\x00\xff"

    capture = _capture()
    capture[8][0][2] = b"\x00\xff"
    _error(validate_raw_collector_capture_v2, capture)


def test_empty_argv_elements_are_preserved_but_nul_is_rejected() -> None:
    capture = _capture()
    events = _events(capture)
    events[2][4].insert(1, "")
    events[10][4][5].insert(1, "")
    events[5][4].append("")
    events[10][4][6].append("")
    _replace_events(capture, events)
    _refresh_invocation(capture)
    validate_raw_collector_capture_v2(capture)

    capture = _capture()
    events = _events(capture)
    events[2][4].append("bad\x00argument")
    _replace_events(capture, events)
    _error(validate_raw_collector_capture_v2, capture)


def test_empty_relative_path_remains_invalid() -> None:
    capture = _capture()
    capture[4][1] = ""
    _error(validate_raw_collector_capture_v2, capture)


def test_path_profile_uses_arrays_only_text_rules_not_argv_rules() -> None:
    capture = _capture()
    profile = ["", "contains\x00nul", [b"opaque"]]
    capture[3][0][3] = profile
    _refresh_namespace_and_runtime_roots(capture)
    events = _events(capture)
    events[10][4][4] = profile
    _replace_events(capture, events)
    _refresh_invocation(capture)
    validate_raw_collector_capture_v2(capture)


def test_second_primary_clang_role_fails_even_with_another_soname() -> None:
    capture = _capture()
    capture[3][0][4][2][1] = [CLANG_CPP_IMPLEMENTATION, RUNTIME_DEPENDENCY]
    _refresh_namespace_and_runtime_roots(capture)
    _error(validate_raw_collector_capture_v2, capture)


def test_actual_open_phases_must_not_regress() -> None:
    capture = _capture()
    first = capture[5][6][0]
    first[1] = 2
    capture[5][6].append([1, 1, *first[2:]])
    _refresh_invocation(capture)
    _error(validate_raw_collector_capture_v2, capture)


def test_decode_rejects_trailing_and_noncanonical_bytes() -> None:
    encoded = encode_raw_collector_capture_v2(_capture())
    _error(decode_raw_collector_capture_v2, encoded + b"\x00")
    _error(decode_raw_collector_capture_v2, eir_canonical_cbor_encode(1))

    capture = _capture()
    # A frame claims a valid nonminimal CBOR array header for five items.  The
    # capture contains only bytes, so this is a genuine byte-observable test.
    capture[5][1] = b"V631CR01" + (2).to_bytes(8, "big") + b"\x98\x05"
    _error(validate_raw_collector_capture_v2, capture)


def test_direct_value_versions_reject_booleans() -> None:
    manifest = _manifest()
    manifest[0] = True
    with pytest.raises(EIRPrebindingError):
        derive_capture_namespace_roots_v1(manifest)

    capture = _capture()
    capture[4][0] = True
    _error(validate_raw_collector_capture_v2, capture)


def test_input_manifests_must_commit_the_primary_source() -> None:
    for manifest_index in (4, 5):
        capture = _capture()
        capture[5][manifest_index][1] = []
        _refresh_invocation(capture)
        _error(validate_raw_collector_capture_v2, capture)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c[6].pop(5),
        lambda c: c[6][5][1].__setitem__(3, 999),
        lambda c: c[6].__setitem__(7, bytes(32)),
        lambda c: c[6][4].append(deepcopy(c[6][4][0])),
        lambda c: c[6][5][1].__setitem__(2, 0),
        lambda c: c[6][5].pop(),
        lambda c: c[6][5][2].__setitem__(0, 9),
        lambda c: c[6][4].pop(2),
        lambda c: c[6][4].pop(1),
        lambda c: c[6][2].__setitem__(4, b"other"),
        lambda c: c[6][3].__setitem__(4, b"other"),
        lambda c: c[6][2].__setitem__(1, "libclang-cpp.so.16"),
        lambda c: c[6][2].__setitem__(1, b"wrong.so"),
        lambda c: c[6][2].__setitem__(1, None),
        lambda c: c[6][2].__setitem__(4, None),
        lambda c: c[6].__setitem__(6, bytes(32)),
        lambda c: c[6][4].append(["lib/unobserved.so", b"", 1, _digest("u"), b""]),
        lambda c: c[6][5][3].__setitem__(2, 99),
        lambda c: c[6][5][1].__setitem__(1, 9),
        lambda c: c[6][5][1].__setitem__(7, 0),
    ],
)
def test_runtime_adversarial_mutations_fail_closed(mutate) -> None:
    capture = _capture()
    mutate(capture)
    _error(validate_raw_collector_capture_v2, capture)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c[5].__setitem__(1, b"X" + c[5][1][1:]),
        lambda c: c[5].__setitem__(1, c[5][1][:15]),
        lambda c: c[5].__setitem__(1, c[5][1] + b"trailing"),
        lambda c: c[5].__setitem__(2, 1),
        lambda c: c[5].__setitem__(3, bytes(32)),
        lambda c: c[5][4][0].__setitem__(0, "different"),
        lambda c: c[5][5][0].__setitem__(0, "different"),
        lambda c: c[5][6][0].__setitem__(1, 2),
    ],
)
def test_receipt_invocation_and_open_trace_mutations_fail_closed(mutate) -> None:
    capture = _capture()
    mutate(capture)
    _error(validate_raw_collector_capture_v2, capture)


def test_receipt_semantic_mutations_fail_closed() -> None:
    capture = _capture()
    events = _events(capture)

    events[0][4][0] = 4
    _replace_events(capture, events)
    _error(validate_raw_collector_capture_v2, capture)

    capture = _capture()
    events = _events(capture)
    events[10][4][7][0][2] = 99
    _replace_events(capture, events)
    _error(validate_raw_collector_capture_v2, capture)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda events: events[3].__setitem__(2, 9),
        lambda events: events[3].__setitem__(2, 2),
        lambda events: events[2].__setitem__(3, 4),
        lambda events: events.append(deepcopy(events[10])),
        lambda events: events[2].__setitem__(4, ["different"]),
        lambda events: events[5].__setitem__(4, ["different"]),
        lambda events: events[10][4].__setitem__(4, ["different-profile"]),
        lambda events: events[10][4][7][0].__setitem__(2, 99),
    ],
)
def test_all_byte_observable_receipt_sequence_mutations_fail_closed(mutate) -> None:
    capture = _capture()
    events = _events(capture)
    mutate(events)
    _replace_events(capture, events)
    _error(validate_raw_collector_capture_v2, capture)


def test_manifest_open_execution_harness_termination_and_cap_checks_fail_closed() -> None:
    capture = _capture()
    capture[3][1] = bytes(32)
    _error(validate_raw_collector_capture_v2, capture)

    capture = _capture()
    capture[4][3] = [["HOME", "bad"]]
    _error(validate_raw_collector_capture_v2, capture)

    capture = _capture()
    capture[4][7] = bytes(32)
    _error(validate_raw_collector_capture_v2, capture)

    capture = _capture()
    capture[4][6] = "other-work"
    _error(validate_raw_collector_capture_v2, capture)

    capture = _capture()
    capture[5][6].clear()
    _error(validate_raw_collector_capture_v2, capture)

    capture = _capture()
    capture[7][0] = RAW_COLLECTOR_CAPTURE_MAX_BYTES_V1 + 1
    _error(validate_raw_collector_capture_v2, capture)

    capture = _capture()
    capture[8][3] = bytes(32)
    _error(validate_raw_collector_capture_v2, capture)

    capture = _capture()
    capture[9][2] = bytes(32)
    _error(validate_raw_collector_capture_v2, capture)
