"""Zero-authority production assembler for RAW_COLLECTOR_CAPTURE_V2.

The only public operation accepts an exact canonical-CBOR native evidence
bridge and the opaque expectations artifact frozen by Python before launch.
The bridge contains observed leaves and exact byte streams, never protocol
records, PASS values, or authority claims.  Its private prelaunch root only
binds the independently retained artifact; it never enters public Capture V2.
This module owns record construction and delegates every protocol formula and
final validation to :mod:`evaluation_v6_3_1.capture_v2`.

The implementation is intentionally incomplete as campaign evidence until a
native Linux/amd64 producer, independent verifier, and dual-origin replay pass
the externally required test matrix.  Successful local assembly carries no
upload, holdout, agent-modification, or permit authority.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from . import capture_v2 as oracle
from .capture_namespace_v1 import (
    CAPTURE_NAMESPACE_MANIFEST_V1,
    COLLECTOR_EXECUTABLE,
    derive_capture_namespace_roots_v1,
    validate_capture_namespace_manifest_v1,
)
from .capture_v2_manifest_v1 import (
    derive_input_manifests_v1,
    validate_argv_grammar_pin,
    validate_path_profile_v2,
)
from .capture_v2_prelaunch_expectations import (
    PrelaunchExpectationsError,
    ValidatedPrelaunchExpectationsV2,
    _validate_frozen_prelaunch_expectations_v2,
)
from .eir_prebinding import (
    EIRPrebindingError,
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
)
from .m0_diagnostic_census import (
    M0DiagnosticCensusError,
    canonicalize_native_diagnostic_transport,
)
from .m0_diagnostic_primitives import (
    M0PrimitiveError,
    canonical_cbor_decode as diagnostic_cbor_decode,
    canonical_cbor_encode as diagnostic_cbor_encode,
    text as primitive_text,
)


PROTOCOL_ID = 631302
NATIVE_PRODUCTION_EVIDENCE_BRIDGE_V3 = 3

CAPTURE_V2_ASSEMBLY_FAILED = "CAPTURE_V2_ASSEMBLY_FAILED"

BRIDGE_MAX_DEPTH = 64
BRIDGE_MAX_NODES = 1_000_000
BRIDGE_MAX_CONTAINER_ITEMS = 250_000
BRIDGE_MAX_TEXT_BYTES = 1 * 1024 * 1024
BRIDGE_MAX_BYTE_STRING_BYTES = 64 * 1024 * 1024
BRIDGE_MAX_ENCODED_BYTES = 128 * 1024 * 1024
UINT64_MAX = (1 << 64) - 1

ZERO_AUTHORITY = True
AUTHORITY = False
UPLOAD_AUTHORITY = False
PERMIT_AUTHORITY = False
HOLDOUT_ACCESS_AUTHORITY = False
AGENT_MODIFICATION_AUTHORITY = False
CALIBRATION_UPLOAD_AUTHORITY = False
PRODUCTION_UPLOAD_AUTHORITY = False
SEALED_HOLDOUT_ACCESS_AUTHORITY = False


class CaptureV2AssemblyError(EIRPrebindingError):
    """A production-evidence bridge failed before any capture was emitted."""

    def __init__(self, message: str) -> None:
        super().__init__(CAPTURE_V2_ASSEMBLY_FAILED, message)


def _fail(message: str) -> CaptureV2AssemblyError:
    return CaptureV2AssemblyError(message)


def _head(major: int, argument: int) -> bytes:
    if argument < 0 or argument > UINT64_MAX:
        raise _fail("bridge CBOR argument is outside uint64")
    if argument < 24:
        return bytes(((major << 5) | argument,))
    if argument <= 0xFF:
        return bytes(((major << 5) | 24, argument))
    if argument <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + argument.to_bytes(2, "big")
    if argument <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + argument.to_bytes(4, "big")
    return bytes(((major << 5) | 27,)) + argument.to_bytes(8, "big")


class _BridgeEncoder:
    """Strict arrays-only CBOR with a 64 MiB evidence-byte-string limit."""

    def __init__(self) -> None:
        self.nodes = 0
        self.active: set[int] = set()

    def _visit(self, depth: int) -> None:
        if depth > BRIDGE_MAX_DEPTH:
            raise _fail("bridge nesting exceeds the profile limit")
        self.nodes += 1
        if self.nodes > BRIDGE_MAX_NODES:
            raise _fail("bridge node count exceeds the profile limit")

    def encode(self, value: Any, depth: int = 0) -> bytes:
        self._visit(depth)
        if type(value) is int:
            if value < 0 or value > UINT64_MAX:
                raise _fail("bridge integer is outside uint64")
            return _head(0, value)
        if type(value) is bytes:
            if len(value) > BRIDGE_MAX_BYTE_STRING_BYTES:
                raise _fail("bridge byte string exceeds the profile limit")
            return _head(2, len(value)) + value
        if type(value) is str:
            try:
                encoded = value.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise _fail("bridge text is not valid UTF-8") from exc
            if len(encoded) > BRIDGE_MAX_TEXT_BYTES:
                raise _fail("bridge text exceeds the profile limit")
            return _head(3, len(encoded)) + encoded
        if type(value) is list:
            if len(value) > BRIDGE_MAX_CONTAINER_ITEMS:
                raise _fail("bridge array exceeds the profile limit")
            identity = id(value)
            if identity in self.active:
                raise _fail("cyclic values cannot be bridge encoded")
            self.active.add(identity)
            try:
                parts = [_head(4, len(value))]
                size = len(parts[0])
                for item in value:
                    encoded_item = self.encode(item, depth + 1)
                    size += len(encoded_item)
                    if size > BRIDGE_MAX_ENCODED_BYTES:
                        raise _fail("bridge value exceeds the encoded-byte limit")
                    parts.append(encoded_item)
                return b"".join(parts)
            finally:
                self.active.remove(identity)
        raise _fail(
            "bridge permits arrays, uints, byte strings, and exact UTF-8 text only"
        )


class _BridgeDecoder:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0
        self.nodes = 0

    def _visit(self, depth: int) -> None:
        if depth > BRIDGE_MAX_DEPTH:
            raise _fail("bridge nesting exceeds the profile limit")
        self.nodes += 1
        if self.nodes > BRIDGE_MAX_NODES:
            raise _fail("bridge node count exceeds the profile limit")

    def _take(self, count: int) -> bytes:
        end = self.offset + count
        if count < 0 or end > len(self.raw):
            raise _fail("bridge CBOR value is truncated")
        value = self.raw[self.offset:end]
        self.offset = end
        return value

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if width is None:
            raise _fail("bridge contains an indefinite or reserved CBOR argument")
        encoded = self._take(width)
        value = int.from_bytes(encoded, "big")
        minimum = {1: 24, 2: 256, 4: 65_536, 8: 1 << 32}[width]
        if value < minimum:
            raise _fail("bridge CBOR integer or length is not shortest-form")
        return value

    def decode(self, depth: int = 0) -> Any:
        self._visit(depth)
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F
        if major == 0:
            return self._argument(additional)
        if major in (2, 3):
            length = self._argument(additional)
            limit = (
                BRIDGE_MAX_BYTE_STRING_BYTES
                if major == 2
                else BRIDGE_MAX_TEXT_BYTES
            )
            if length > limit:
                raise _fail("bridge CBOR string exceeds the profile limit")
            payload = self._take(length)
            if major == 2:
                return payload
            try:
                return payload.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise _fail("bridge text is not valid UTF-8") from exc
        if major == 4:
            length = self._argument(additional)
            if length > BRIDGE_MAX_CONTAINER_ITEMS:
                raise _fail("bridge array exceeds the profile limit")
            return [self.decode(depth + 1) for _ in range(length)]
        raise _fail(
            "bridge forbids maps, negative integers, tags, simple values, "
            "floats, and indefinite items"
        )


def _bridge_encode(value: Any) -> bytes:
    encoded = _BridgeEncoder().encode(value)
    if not encoded or len(encoded) > BRIDGE_MAX_ENCODED_BYTES:
        raise _fail("bridge encoding is empty or exceeds the byte limit")
    return encoded


def _bridge_decode(raw: bytes) -> list[Any]:
    if type(raw) is not bytes:
        raise _fail("native production evidence must be immutable bytes")
    if not raw or len(raw) > BRIDGE_MAX_ENCODED_BYTES:
        raise _fail("native production evidence is empty or exceeds the byte limit")
    decoder = _BridgeDecoder(raw)
    value = decoder.decode()
    if decoder.offset != len(raw):
        raise _fail("trailing bytes follow the native production evidence")
    if type(value) is not list:
        raise _fail("native production evidence must be a top-level array")
    if _bridge_encode(value) != raw:
        raise _fail("native production evidence is not canonical CBOR")
    return value


def _list(value: Any, label: str, width: int | None = None) -> list[Any]:
    if type(value) is not list:
        raise _fail(f"{label} must be an array")
    if width is not None and len(value) != width:
        raise _fail(f"{label} must contain exactly {width} fields")
    return value


def _uint(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > UINT64_MAX:
        raise _fail(f"{label} must be uint64")
    if positive and value == 0:
        raise _fail(f"{label} must be positive")
    return value


def _bstr(value: Any, label: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise _fail(f"{label} must be a byte string")
    if length is not None and len(value) != length:
        raise _fail(f"{label} must be exactly {length} bytes")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise _fail(f"{label} must be nonempty NUL-free text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(f"{label} must be valid UTF-8") from exc
    return value


def _profile_build_label_text(value: Any) -> str:
    try:
        return primitive_text(value, "collector profile build label text")
    except M0PrimitiveError as exc:
        raise _fail(
            "collector profile build label violates the frozen ASCII grammar"
        ) from exc


def _component_facts(value: Any, label: str) -> list[Any]:
    row = _list(value, label, 3)
    _uint(row[0], f"{label}.byte_length", positive=True)
    _bstr(row[1], f"{label}.sha256", 32)
    build_id = _bstr(row[2], f"{label}.build_id")
    if len(build_id) > 65_535:
        raise _fail(f"{label}.build_id exceeds 65535 bytes")
    return deepcopy(row)


def _runtime_object_facts(value: Any, label: str) -> list[Any]:
    row = _list(value, label, 5)
    oracle._relative_path(row[0], f"{label}.path")
    soname = _bstr(row[1], f"{label}.soname")
    if len(soname) > 65_535 or (soname and b"\x00" in soname):
        raise _fail(f"{label}.soname has invalid byte representation")
    _uint(row[2], f"{label}.byte_length", positive=True)
    _bstr(row[3], f"{label}.sha256", 32)
    build_id = _bstr(row[4], f"{label}.build_id")
    if len(build_id) > 65_535:
        raise _fail(f"{label}.build_id exceeds 65535 bytes")
    return deepcopy(row)


def _runtime_observation_facts(value: Any, label: str) -> list[Any]:
    row = _list(value, label, 8)
    for index, item in enumerate(row):
        _uint(item, f"{label}[{index}]")
    return deepcopy(row)


def _public_component_record(value: Any, label: str) -> list[Any]:
    """Project one private opaque harness ID into the public text protocol."""
    row = _component_facts(value, label)
    raw_build_id = row[2]
    if not raw_build_id:
        raise _fail(f"{label}.build_id must be nonempty for public emission")
    public_build_id = raw_build_id.hex()
    if bytes.fromhex(public_build_id) != raw_build_id or public_build_id != public_build_id.lower():
        raise _fail(f"{label}.build_id public projection is not canonical")
    return [row[0], row[1], public_build_id]


@dataclass(frozen=True)
class _VerifiedProductionNativeEvidence:
    collector_profile_build_label_text: str
    observed_collector_gnu_build_id_descriptor_bytes: bytes
    collector_profile_cbor_bytes: bytes
    collector_profile: list[Any]
    argv_grammar_version: int
    argv_grammar_sha256: bytes
    validated_prelaunch_expectations_root: bytes
    namespace_manifest: list[Any]
    working_directory_relative_path: str
    path_profile_cbor: bytes
    namespace_identity_rows: list[Any]
    execution_facts: list[Any]
    receipt_stream: bytes
    actual_open_rows: list[Any]
    runtime_facts: list[Any]
    stdout_bytes: bytes
    harness_facts: list[Any]
    exit_status: int
    stderr_bytes: bytes


def _decode_path_profile(raw: Any) -> list[Any]:
    encoded = _bstr(raw, "namespace path_profile_cbor")
    try:
        value = eir_canonical_cbor_decode(encoded)
    except EIRPrebindingError as exc:
        raise _fail("namespace path profile is not canonical arrays-only CBOR") from exc
    if eir_canonical_cbor_encode(value) != encoded:
        raise _fail("namespace path profile is not byte-canonical")
    return value


def _strict_decode_native_bridge(raw: bytes) -> _VerifiedProductionNativeEvidence:
    bridge = _list(_bridge_decode(raw), "native production evidence", 10)
    if _uint(bridge[0], "bridge protocol") != PROTOCOL_ID:
        raise _fail("native bridge protocol is not 631302")
    if _uint(bridge[1], "bridge version") != NATIVE_PRODUCTION_EVIDENCE_BRIDGE_V3:
        raise _fail("native bridge version is not 3")

    collector_facts = _list(bridge[2], "collector_facts_v3", 5)
    collector_profile_build_label_text = _profile_build_label_text(
        collector_facts[0]
    )
    observed_collector_gnu_build_id_descriptor_bytes = _bstr(
        collector_facts[1],
        "observed collector GNU build-ID descriptor bytes",
    )
    if len(observed_collector_gnu_build_id_descriptor_bytes) > 65_535:
        raise _fail(
            "observed collector GNU build-ID descriptor exceeds 65535 bytes"
        )
    collector_profile_cbor = _bstr(
        collector_facts[2], "prelaunch collector profile CBOR"
    )
    try:
        collector_profile = diagnostic_cbor_decode(collector_profile_cbor)
    except (M0PrimitiveError, TypeError, ValueError) as exc:
        raise _fail("prelaunch collector profile is not canonical CBOR") from exc
    try:
        collector_profile_build_label = _profile_build_label_text(
            collector_profile[1]
        )
    except (IndexError, TypeError) as exc:
        raise _fail("collector profile has no build label text at field 1") from exc
    if collector_profile_build_label != collector_profile_build_label_text:
        raise _fail(
            "collector profile build label text does not match collector facts"
        )
    argv_grammar_version = _uint(
        collector_facts[3], "argv grammar version", positive=True
    )
    argv_grammar_sha256 = _bstr(
        collector_facts[4], "argv grammar sha256", 32
    )
    try:
        validate_argv_grammar_pin(argv_grammar_version, argv_grammar_sha256)
    except EIRPrebindingError as exc:
        raise _fail("native bridge does not bind the frozen argv grammar") from exc

    namespace_facts = _list(bridge[3], "namespace_facts", 5)
    working_directory_relative_path = oracle._relative_path(
        namespace_facts[0], "namespace working directory"
    )
    primary_source = _text(namespace_facts[1], "namespace primary source")
    path_profile_cbor = _bstr(namespace_facts[2], "namespace path_profile_cbor")
    path_profile = _decode_path_profile(path_profile_cbor)
    try:
        checked_path_profile = validate_path_profile_v2(
            path_profile, working_directory_relative_path
        )
    except EIRPrebindingError as exc:
        raise _fail("native namespace path profile is not PATH_PROFILE_V2") from exc
    file_rows = deepcopy(_list(namespace_facts[3], "namespace file_rows"))
    namespace_identity_rows = deepcopy(
        _list(namespace_facts[4], "namespace identity rows")
    )
    manifest = [
        CAPTURE_NAMESPACE_MANIFEST_V1,
        checked_path_profile.working_directory_relative_path,
        primary_source,
        path_profile,
        file_rows,
    ]
    try:
        validate_capture_namespace_manifest_v1(manifest)
    except EIRPrebindingError as exc:
        raise _fail("native namespace facts do not form a valid manifest") from exc

    execution_facts_bound = _list(
        bridge[4], "execution_facts_bound_v3", 2
    )
    execution_facts = deepcopy(
        _list(execution_facts_bound[0], "execution_facts_v2", 4)
    )
    validated_prelaunch_expectations_root = _bstr(
        execution_facts_bound[1],
        "validated prelaunch expectations root",
        32,
    )
    oracle._argv(execution_facts[0], "execution argv")
    execution_cwd = oracle._relative_path(execution_facts[1], "execution cwd")
    _uint(execution_facts[2], "execution proc_exe length", positive=True)
    _bstr(execution_facts[3], "execution proc_exe sha256", 32)
    if execution_cwd != working_directory_relative_path:
        raise _fail("execution cwd differs from namespace working directory")

    invocation_facts = _list(bridge[5], "invocation_facts", 2)
    receipt_stream = _bstr(invocation_facts[0], "exact FD3 receipt stream")
    actual_open_rows = deepcopy(_list(invocation_facts[1], "actual open rows"))

    raw_runtime_facts = _list(bridge[6], "runtime_facts", 4)
    raw_runtime_objects = _list(raw_runtime_facts[2], "runtime object rows")
    raw_runtime_observations = _list(
        raw_runtime_facts[3], "runtime observation rows"
    )
    runtime_facts = [
        _runtime_object_facts(raw_runtime_facts[0], "primary runtime object"),
        _runtime_object_facts(raw_runtime_facts[1], "runtime interpreter object"),
        [
            _runtime_object_facts(row, f"runtime object rows[{index}]")
            for index, row in enumerate(raw_runtime_objects)
        ],
        [
            _runtime_observation_facts(
                row, f"runtime observation rows[{index}]"
            )
            for index, row in enumerate(raw_runtime_observations)
        ],
    ]

    output_facts = _list(bridge[7], "output_facts", 1)
    stdout_bytes = _bstr(output_facts[0], "exact collector stdout")
    if not stdout_bytes or len(stdout_bytes) > oracle.RAW_COLLECTOR_CAPTURE_MAX_BYTES_V1:
        raise _fail("collector stdout is empty or exceeds the Capture V2 cap")
    try:
        # Capture V2 is a custody record, not a census-success assertion.  It
        # preserves structurally valid template-unproven results byte-for-byte;
        # the downstream census entrypoint emits status 2 for those bytes.
        canonical_census = canonicalize_native_diagnostic_transport(
            stdout_bytes,
            collector_profile=collector_profile,
            bound_profile_cbor=collector_profile_cbor,
            allow_template_unproven=True,
        )
    except (M0DiagnosticCensusError, M0PrimitiveError, TypeError, ValueError) as exc:
        raise _fail(
            "collector stdout is not a valid bound native diagnostic transport"
        ) from exc
    collector_profile = canonical_census[2]
    if diagnostic_cbor_encode(collector_profile) != collector_profile_cbor:
        raise _fail("collector profile differs from its exact prelaunch bytes")

    harness_facts = _list(bridge[8], "harness_facts", 3)
    checked_harness = [
        _component_facts(harness_facts[0], "capture entry facts"),
        _component_facts(harness_facts[1], "capture interpreter facts"),
        _component_facts(harness_facts[2], "native supervisor facts"),
    ]
    if checked_harness[0] != checked_harness[2]:
        raise _fail(
            "native bridge harness is not DIRECT_DYNAMIC_ELF_SUPERVISOR_V1: "
            "capture entry and supervisor must be the same observed ELF"
        )
    if checked_harness[1] == checked_harness[0]:
        raise _fail(
            "native bridge harness is not DIRECT_DYNAMIC_ELF_SUPERVISOR_V1: "
            "capture interpreter must be a distinct observed ELF"
        )

    termination_facts = _list(bridge[9], "termination_facts", 2)
    exit_status = _uint(termination_facts[0], "collector exit status")
    stderr_bytes = _bstr(termination_facts[1], "exact collector stderr")
    if exit_status != 0 or stderr_bytes:
        raise _fail("failure evidence cannot enter successful Capture V2 assembly")

    return _VerifiedProductionNativeEvidence(
        collector_profile_build_label_text=collector_profile_build_label_text,
        observed_collector_gnu_build_id_descriptor_bytes=(
            observed_collector_gnu_build_id_descriptor_bytes
        ),
        collector_profile_cbor_bytes=collector_profile_cbor,
        collector_profile=collector_profile,
        argv_grammar_version=argv_grammar_version,
        argv_grammar_sha256=argv_grammar_sha256,
        validated_prelaunch_expectations_root=(
            validated_prelaunch_expectations_root
        ),
        namespace_manifest=manifest,
        working_directory_relative_path=working_directory_relative_path,
        path_profile_cbor=path_profile_cbor,
        namespace_identity_rows=namespace_identity_rows,
        execution_facts=execution_facts,
        receipt_stream=receipt_stream,
        actual_open_rows=actual_open_rows,
        runtime_facts=runtime_facts,
        stdout_bytes=stdout_bytes,
        harness_facts=checked_harness,
        exit_status=exit_status,
        stderr_bytes=stderr_bytes,
    )


def _validate_prelaunch_binding(
    evidence: _VerifiedProductionNativeEvidence,
    artifact: ValidatedPrelaunchExpectationsV2,
) -> None:
    try:
        expected = _validate_frozen_prelaunch_expectations_v2(artifact)
    except PrelaunchExpectationsError as exc:
        raise _fail(str(exc)) from exc

    if (
        evidence.validated_prelaunch_expectations_root
        != artifact.validated_prelaunch_expectations_root
    ):
        raise _fail(
            "native bridge prelaunch root differs from the frozen artifact"
        )

    observed = [
        evidence.collector_profile_build_label_text,
        evidence.observed_collector_gnu_build_id_descriptor_bytes,
        evidence.collector_profile_cbor_bytes,
        evidence.argv_grammar_version,
        evidence.argv_grammar_sha256,
    ]
    if observed != expected[3:8]:
        labels = (
            "collector profile build label",
            "collector GNU build-ID descriptor",
            "collector profile CBOR",
            "argv grammar version",
            "argv grammar sha256",
        )
        for label, actual, frozen in zip(labels, observed, expected[3:8]):
            if actual != frozen:
                raise _fail(
                    f"native {label} differs from the frozen prelaunch artifact"
                )
        raise _fail("native collector facts differ from the prelaunch artifact")

    if evidence.working_directory_relative_path != artifact.working_directory_relative_path:
        raise _fail("native namespace CWD differs from the prelaunch artifact")
    if evidence.namespace_manifest[2] != artifact.primary_source_relative_path:
        raise _fail("native primary source differs from the prelaunch artifact")
    if evidence.path_profile_cbor != artifact.path_profile_cbor_bytes:
        raise _fail("native path profile differs from the prelaunch artifact")

    observed_public_rows_cbor = eir_canonical_cbor_encode(
        evidence.namespace_manifest[4]
    )
    if observed_public_rows_cbor != artifact.public_file_rows_cbor_bytes:
        raise _fail("native public file rows differ from the prelaunch artifact")

    try:
        path_profile = eir_canonical_cbor_decode(
            artifact.path_profile_cbor_bytes
        )
    except EIRPrebindingError as exc:
        raise _fail("frozen path profile cannot derive collector argv") from exc
    capture_context = eir_canonical_cbor_encode(
        [1, artifact.primary_source_relative_path, path_profile]
    )
    expected_execution_argv = [
        "/bin/collector",
        "--protocol=631302",
        "--level=2",
        "--primary-source=/" + artifact.primary_source_relative_path,
        "--capture-context-v1-cbor-hex=" + capture_context.hex(),
        "--",
        *artifact.requested_argv,
    ]
    if evidence.execution_facts[0] != expected_execution_argv:
        raise _fail(
            "native execution argv differs from the exact derived collector launch"
        )

    expected_harness = [list(row) for row in artifact.harness_expectations]
    if evidence.harness_facts != expected_harness:
        raise _fail("native harness facts differ from the prelaunch artifact")

    try:
        _, receipt_driver_argv, _ = oracle._parse_receipt_stream(
            evidence.receipt_stream, evidence.namespace_manifest
        )
    except EIRPrebindingError as exc:
        raise _fail("native receipt cannot be bound to prelaunch argv") from exc
    if receipt_driver_argv != list(artifact.requested_argv):
        raise _fail("receipt driver argv differs from the prelaunch artifact")

    if evidence.collector_profile[1] != expected[3]:
        raise _fail(
            "collector profile field 1 differs from the frozen prelaunch label"
        )


def _collector_file_row(manifest: list[Any]) -> list[Any]:
    rows = [row for row in manifest[4] if COLLECTOR_EXECUTABLE in row[1]]
    if len(rows) != 1:
        raise _fail("namespace does not contain exactly one collector")
    return rows[0]


def _collector_runtime_object_row(
    runtime_facts: list[Any], collector_file: list[Any]
) -> list[Any]:
    """Find the uniquely identified collector row in runtime observations."""

    objects = _list(runtime_facts[2], "runtime object rows")
    matches: list[list[Any]] = []
    for index, value in enumerate(objects):
        row = _list(value, f"runtime object rows[{index}]", 5)
        path = oracle._relative_path(row[0], f"runtime object rows[{index}].path")
        byte_length = _uint(
            row[2], f"runtime object rows[{index}].byte_length", positive=True
        )
        digest = _bstr(row[3], f"runtime object rows[{index}].sha256", 32)
        descriptor = _bstr(
            row[4],
            f"runtime object rows[{index}].GNU build-ID descriptor bytes",
        )
        if (
            path == collector_file[0]
            and byte_length == collector_file[3]
            and digest == collector_file[4]
        ):
            matches.append([row[0], row[1], byte_length, digest, descriptor])
    if len(matches) != 1:
        raise _fail(
            "collector runtime object is not uniquely identified by the sealed "
            "collector path, length, and digest"
        )
    return matches[0]


def _linux_device_pair(raw_device: int) -> tuple[int, int]:
    """Decode Linux dev_t without depending on the assembler host kernel."""

    major = ((raw_device >> 8) & 0xFFF) | ((raw_device >> 32) & 0xFFFFF000)
    minor = (raw_device & 0xFF) | ((raw_device >> 12) & 0xFFFFFF00)
    return major, minor


def _public_actual_open_rows(private_rows_value: Any) -> list[list[Any]]:
    """Remove the private-only mode leaf after frozen-identity validation."""

    public_rows: list[list[Any]] = []
    for index, row_value in enumerate(_list(private_rows_value, "actual open rows")):
        row = _list(row_value, f"actual open rows[{index}]", 9)
        public_rows.append(deepcopy(row[:6] + row[7:]))
    return public_rows


def _validate_runtime_observation_identities(
    runtime_facts: list[Any], namespace_identity_rows: list[Any]
) -> None:
    identity_by_path: dict[str, list[Any]] = {}
    for index, row_value in enumerate(namespace_identity_rows):
        row = _list(row_value, f"namespace identity rows[{index}]", 7)
        path = oracle._relative_path(row[0], f"namespace identity rows[{index}].path")
        device = _list(row[1], f"namespace identity rows[{index}].device", 2)
        _uint(device[0], "namespace identity device major")
        _uint(device[1], "namespace identity device minor")
        _uint(row[2], "namespace identity inode", positive=True)
        identity_by_path[path] = row

    objects = _list(runtime_facts[2], "runtime object rows")
    observations = _list(runtime_facts[3], "runtime observation rows")
    for sequence, row_value in enumerate(observations):
        row = _list(row_value, f"runtime observation rows[{sequence}]", 8)
        object_index = _uint(row[2], "runtime observation object index")
        if object_index >= len(objects):
            raise _fail("runtime observation object index is out of range")
        object_row = _list(objects[object_index], f"runtime object rows[{object_index}]", 5)
        path = oracle._relative_path(
            object_row[0], f"runtime object rows[{object_index}].path"
        )
        identity = identity_by_path.get(path)
        if identity is None:
            raise _fail("runtime observation object lacks a namespace identity")
        raw_device = _uint(row[3], "runtime observation st_dev")
        inode = _uint(row[4], "runtime observation st_ino", positive=True)
        if _linux_device_pair(raw_device) != tuple(identity[1]) or inode != identity[2]:
            raise _fail("runtime observation differs from its sealed namespace identity")


def _assemble_verified(evidence: _VerifiedProductionNativeEvidence) -> bytes:
    manifest = evidence.namespace_manifest
    namespace_roots = derive_capture_namespace_roots_v1(manifest)
    namespace_record = [
        manifest,
        namespace_roots.source_root,
        namespace_roots.runtime_root,
        namespace_roots.execution_namespace_root,
    ]

    collector_file = _collector_file_row(manifest)
    if evidence.collector_profile[0] != collector_file[4]:
        raise _fail("collector profile hash does not match the sealed collector")
    collector_record = [
        collector_file[3],
        collector_file[4],
        evidence.collector_profile_build_label_text,
    ]

    namespace_rows = {row[0]: row for row in manifest[4]}
    final_receipt, driver_argv, cc1_argv = oracle._parse_receipt_stream(
        evidence.receipt_stream, manifest
    )
    if eir_canonical_cbor_encode(final_receipt[4]) != evidence.path_profile_cbor:
        raise _fail("receipt path profile bytes differ from the bridge custody bytes")
    try:
        derived_manifests = derive_input_manifests_v1(
            argv_grammar_version=evidence.argv_grammar_version,
            argv_grammar_sha256=evidence.argv_grammar_sha256,
            working_directory_relative_path=evidence.working_directory_relative_path,
            primary_source_relative_path=manifest[2],
            path_profile=manifest[3],
            public_file_rows=manifest[4],
            namespace_identity_rows=evidence.namespace_identity_rows,
            driver_argv=driver_argv,
            cc1_argv=cc1_argv,
            actual_open_rows=evidence.actual_open_rows,
        )
    except EIRPrebindingError as exc:
        raise _fail("input manifests cannot be derived from exact bridge leaves") from exc
    driver_manifest = derived_manifests.driver_manifest
    cc1_manifest = derived_manifests.cc1_manifest
    actual_open_rows = oracle._actual_open_rows(
        _public_actual_open_rows(evidence.actual_open_rows), namespace_rows
    )
    actual_open_root = oracle._actual_open_trace_root_v1(actual_open_rows)
    oracle._input_manifest(
        driver_manifest,
        "driver_input_manifest",
        driver_argv,
        1,
        manifest[2],
        namespace_rows,
        actual_open_rows,
    )
    oracle._input_manifest(
        cc1_manifest,
        "cc1_input_manifest",
        cc1_argv,
        2,
        manifest[2],
        namespace_rows,
        actual_open_rows,
    )
    receipt_hash = sha256(evidence.receipt_stream).digest()
    invocation_root = oracle._root(
        oracle.DS_INVOCATION,
        PROTOCOL_ID,
        oracle.ACTUAL_COLLECTOR_INVOCATION_V2,
        len(evidence.receipt_stream),
        receipt_hash,
        final_receipt,
        driver_manifest,
        cc1_manifest,
        actual_open_root,
    )
    invocation_record = [
        oracle.ACTUAL_COLLECTOR_INVOCATION_V2,
        evidence.receipt_stream,
        len(evidence.receipt_stream),
        receipt_hash,
        driver_manifest,
        cc1_manifest,
        actual_open_rows,
        invocation_root,
    ]

    execution_argv, execution_cwd, proc_exe_length, proc_exe_hash = (
        evidence.execution_facts
    )
    if execution_cwd != manifest[1]:
        raise _fail("execution cwd differs from the frozen namespace working directory")
    collector_path = collector_file[0]
    if execution_argv[0] != "/" + collector_path:
        raise _fail("execution argv[0] is not the sealed collector path")
    execution_record = [
        oracle.COLLECTOR_EXECUTION_RECORD_V1,
        collector_path,
        execution_argv,
        [],
        proc_exe_length,
        proc_exe_hash,
        execution_cwd,
        actual_open_root,
    ]

    primary, interpreter, runtime_objects, runtime_observations = (
        evidence.runtime_facts
    )
    collector_runtime_object = _collector_runtime_object_row(
        evidence.runtime_facts, collector_file
    )
    if (
        collector_runtime_object[4]
        != evidence.observed_collector_gnu_build_id_descriptor_bytes
    ):
        raise _fail(
            "observed collector GNU build-ID descriptor differs from the "
            "identified collector runtime object"
        )
    _validate_runtime_observation_identities(
        evidence.runtime_facts, evidence.namespace_identity_rows
    )
    if evidence.collector_profile[2] != primary[3]:
        raise _fail(
            "collector profile Clang implementation hash does not match "
            "the observed primary runtime object"
        )
    observation_root = oracle._root(
        oracle.DS_RUNTIME_OBSERVATION,
        PROTOCOL_ID,
        oracle.CLANG_RUNTIME_BINDING_V2,
        runtime_objects,
        runtime_observations,
    )
    runtime_closure_root = oracle._root(
        oracle.DS_RUNTIME_CLOSURE,
        PROTOCOL_ID,
        oracle.CLANG_RUNTIME_BINDING_V2,
        16,
        primary,
        interpreter,
        runtime_objects,
        runtime_observations,
        namespace_roots.runtime_root,
        observation_root,
    )
    runtime_binding = [
        oracle.CLANG_RUNTIME_BINDING_V2,
        16,
        primary,
        interpreter,
        runtime_objects,
        runtime_observations,
        namespace_roots.runtime_root,
        observation_root,
        runtime_closure_root,
    ]

    raw_collector_record = [
        len(evidence.stdout_bytes),
        sha256(evidence.stdout_bytes).digest(),
    ]

    entry, interpreter_component, supervisor = evidence.harness_facts
    public_entry = _public_component_record(entry, "harness.entry")
    public_interpreter_component = _public_component_record(
        interpreter_component,
        "harness.interpreter",
    )
    public_supervisor = _public_component_record(supervisor, "harness.supervisor")
    harness_root = oracle._root(
        oracle.DS_HARNESS_CLOSURE,
        PROTOCOL_ID,
        1,
        public_entry,
        public_interpreter_component,
        public_supervisor,
    )
    harness_record = [
        public_entry,
        public_interpreter_component,
        public_supervisor,
        harness_root,
    ]

    termination_record = [
        evidence.exit_status,
        len(evidence.stderr_bytes),
        sha256(evidence.stderr_bytes).digest(),
    ]

    capture = [
        PROTOCOL_ID,
        oracle.RAW_COLLECTOR_CAPTURE_V2,
        collector_record,
        namespace_record,
        execution_record,
        invocation_record,
        runtime_binding,
        raw_collector_record,
        harness_record,
        termination_record,
    ]

    roots_before = oracle.validate_raw_collector_capture_v2(capture)
    encoded = oracle.encode_raw_collector_capture_v2(capture)
    decoded_value = eir_canonical_cbor_decode(encoded)
    if decoded_value != capture:
        raise _fail("emitted Capture V2 bytes do not decode to the assembled value")
    roots_after = oracle.decode_raw_collector_capture_v2(encoded)
    if roots_after != roots_before:
        raise _fail("Capture V2 roots changed after emission")
    if eir_canonical_cbor_encode(decoded_value) != encoded:
        raise _fail("emitted Capture V2 bytes are not byte-canonical")
    return encoded


def assemble_capture_v2_production(
    native_production_evidence_cbor: bytes,
    validated_prelaunch_expectations: ValidatedPrelaunchExpectationsV2,
    /,
) -> bytes:
    """Assemble one complete Capture V2 value from exact native leaf evidence.

    The operation is pure and all-or-nothing.  It returns only complete,
    self-validating canonical bytes.  Any failure raises
    :class:`CaptureV2AssemblyError`; no partial record or root is returned.
    """

    try:
        evidence = _strict_decode_native_bridge(native_production_evidence_cbor)
        _validate_prelaunch_binding(evidence, validated_prelaunch_expectations)
        return _assemble_verified(evidence)
    except CaptureV2AssemblyError:
        raise
    except EIRPrebindingError as exc:
        raise _fail(str(exc)) from exc


def assemble_production_capture_v2(
    native_production_evidence_cbor: bytes,
    validated_prelaunch_expectations: ValidatedPrelaunchExpectationsV2,
    /,
) -> bytes:
    """Retired compatibility wrapper; not the authoritative production name."""

    return assemble_capture_v2_production(
        native_production_evidence_cbor,
        validated_prelaunch_expectations,
    )


__all__ = [
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "CAPTURE_V2_ASSEMBLY_FAILED",
    "CaptureV2AssemblyError",
    "assemble_capture_v2_production",
    "HOLDOUT_ACCESS_AUTHORITY",
    "NATIVE_PRODUCTION_EVIDENCE_BRIDGE_V3",
    "PERMIT_AUTHORITY",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "SEALED_HOLDOUT_ACCESS_AUTHORITY",
    "UPLOAD_AUTHORITY",
    "ValidatedPrelaunchExpectationsV2",
    "assemble_production_capture_v2",
]
