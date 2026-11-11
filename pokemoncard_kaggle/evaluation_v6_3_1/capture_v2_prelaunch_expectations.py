"""Opaque, zero-authority prelaunch expectations for Capture V2 Bridge V3.

The artifact is frozen by the Python prelaunch validator before native launch.
It is not a protocol record or authority token.  The production assembler uses
it only to verify that native observations are bound to independently frozen
collector expectations.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from .capture_v2_manifest_v1 import (
    validate_argv_grammar_pin,
    validate_path_profile_v2,
    validate_requested_driver_argv_v1,
)
from .eir_prebinding import (
    EIRPrebindingError,
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
)
from .m0_diagnostic_census import M0DiagnosticCensusError, _collector_profile
from .m0_diagnostic_primitives import (
    M0PrimitiveError,
    canonical_cbor_decode as diagnostic_cbor_decode,
    canonical_cbor_encode as diagnostic_cbor_encode,
    text as primitive_text,
)


PROTOCOL_ID = 631302
VALIDATED_PRELAUNCH_EXPECTATIONS_VERSION_V2 = 2
RAW_PRELAUNCH_REQUEST_VERSION_V1 = 1
VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2 = (
    b"V631302_VALIDATED_PRELAUNCH_EXPECTATIONS_V2\0"
)
MAXIMUM_PROFILE_BUILD_LABEL_BYTES_V1 = 1_048_576
MAXIMUM_GNU_BUILD_ID_DESCRIPTOR_BYTES_V1 = 65_535

PRELAUNCH_EXPECTATIONS_INVALID = "PRELAUNCH_EXPECTATIONS_INVALID"

ZERO_AUTHORITY = True
AUTHORITY = False
UPLOAD_AUTHORITY = False
PERMIT_AUTHORITY = False
HOLDOUT_ACCESS_AUTHORITY = False
AGENT_MODIFICATION_AUTHORITY = False
CALIBRATION_UPLOAD_AUTHORITY = False
PRODUCTION_UPLOAD_AUTHORITY = False
SEALED_HOLDOUT_ACCESS_AUTHORITY = False


class PrelaunchExpectationsError(EIRPrebindingError):
    def __init__(self, message: str) -> None:
        super().__init__(PRELAUNCH_EXPECTATIONS_INVALID, message)


def _fail(message: str) -> PrelaunchExpectationsError:
    return PrelaunchExpectationsError(message)


def _profile_label(value: Any) -> str:
    try:
        label = primitive_text(value, "collector profile build label")
    except M0PrimitiveError as exc:
        raise _fail(
            "collector profile build label violates the frozen ASCII grammar"
        ) from exc
    return label


def _descriptor(value: Any) -> bytes:
    if type(value) is not bytes:
        raise _fail("expected collector GNU build-ID descriptor must be bytes")
    # The legacy opaque expectations artifact permits an absent independent
    # build-ID descriptor.  RAW_PRELAUNCH_REQUEST_V1 applies its stricter
    # 1..65535-byte wire rule at the handoff boundary.
    if len(value) > MAXIMUM_GNU_BUILD_ID_DESCRIPTOR_BYTES_V1:
        raise _fail("expected collector GNU build-ID descriptor exceeds 65535 bytes")
    return bytes(value)


def _digest(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise _fail(f"{label} must be exactly 32 bytes")
    return bytes(value)


def _uint(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise _fail(f"{label} must be a canonical uint64")
    return value


def _collector_profile_bytes(value: Any, expected_label: str) -> bytes:
    if type(value) is not bytes or not value:
        raise _fail("collector profile must be nonempty canonical CBOR bytes")
    raw = bytes(value)
    try:
        decoded = diagnostic_cbor_decode(raw)
        normalized = _collector_profile(decoded, raw)
    except (M0DiagnosticCensusError, M0PrimitiveError, TypeError, ValueError) as exc:
        raise _fail("collector profile is not the frozen canonical profile") from exc
    if diagnostic_cbor_encode(normalized) != raw:
        raise _fail("collector profile is not byte-canonical")
    try:
        embedded_label = _profile_label(normalized[1])
    except (IndexError, TypeError) as exc:
        raise _fail("collector profile has no build label at field 1") from exc
    if embedded_label != expected_label:
        raise _fail("collector profile field 1 differs from its frozen label")
    return raw


def _validated_value(
    collector_profile_build_label_text: Any,
    expected_collector_gnu_build_id_descriptor_bytes: Any,
    collector_profile_cbor_bytes: Any,
    argv_grammar_version: Any,
    argv_grammar_sha256: Any,
    path_profile_cbor_bytes: Any,
    working_directory_relative_path: Any,
    primary_source_relative_path: Any,
) -> list[Any]:
    label = _profile_label(collector_profile_build_label_text)
    descriptor = _descriptor(expected_collector_gnu_build_id_descriptor_bytes)
    collector_profile = _collector_profile_bytes(collector_profile_cbor_bytes, label)
    grammar_version = _uint(argv_grammar_version, "argv grammar version")
    grammar_sha256 = _digest(argv_grammar_sha256, "argv grammar sha256")
    try:
        validate_argv_grammar_pin(grammar_version, grammar_sha256)
    except EIRPrebindingError as exc:
        raise _fail("prelaunch expectations do not bind the frozen argv grammar") from exc
    if type(path_profile_cbor_bytes) is not bytes or not path_profile_cbor_bytes:
        raise _fail("path profile must be nonempty canonical CBOR bytes")
    try:
        path_profile = eir_canonical_cbor_decode(path_profile_cbor_bytes)
        validate_path_profile_v2(path_profile, working_directory_relative_path)
    except (EIRPrebindingError, TypeError, ValueError) as exc:
        raise _fail("prelaunch expectations do not bind PATH_PROFILE_V2") from exc
    if eir_canonical_cbor_encode(path_profile) != path_profile_cbor_bytes:
        raise _fail("path profile bytes are not canonical")
    if type(primary_source_relative_path) is not str:
        raise _fail("primary source must be a relative path")
    if primary_source_relative_path.startswith("/") or "\x00" in primary_source_relative_path:
        raise _fail("primary source must be a relative path")
    if any(component in ("", ".", "..") for component in primary_source_relative_path.split("/")):
        raise _fail("primary source is not canonical")
    if not primary_source_relative_path.startswith("src/"):
        raise _fail("primary source is outside PATH_PROFILE_V2 source prefix")
    return [
        PROTOCOL_ID,
        RAW_PRELAUNCH_REQUEST_VERSION_V1,
        label,
        descriptor,
        collector_profile,
        grammar_version,
        grammar_sha256,
        bytes(path_profile_cbor_bytes),
        working_directory_relative_path,
        primary_source_relative_path,
    ]


class _PrelaunchValidatorAuthority:
    __slots__ = ()


_PRELAUNCH_VALIDATOR_AUTHORITY = _PrelaunchValidatorAuthority()


def _raw_label_v2(value: Any) -> str:
    label = _profile_label(value)
    encoded = label.encode("utf-8")
    if not 1 <= len(encoded) <= MAXIMUM_PROFILE_BUILD_LABEL_BYTES_V1:
        raise _fail("collector profile build label is outside the frozen byte range")
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise _fail("collector profile build label is not printable ASCII")
    return label


def _validated_value_v2(
    collector_profile_build_label_text: Any,
    expected_collector_gnu_build_id_descriptor_bytes: Any,
    collector_profile_cbor_bytes: Any,
    argv_grammar_version: Any,
    argv_grammar_sha256: Any,
    path_profile_cbor_bytes: Any,
    working_directory_relative_path: Any,
    primary_source_relative_path: Any,
    public_file_rows_cbor_bytes: Any,
    requested_argv: Any,
    harness_expectations: Any,
) -> list[Any]:
    """Validate every semantic raw-request leaf before the V2 root exists."""

    label = _raw_label_v2(collector_profile_build_label_text)
    base = _validated_value(
        label,
        expected_collector_gnu_build_id_descriptor_bytes,
        collector_profile_cbor_bytes,
        argv_grammar_version,
        argv_grammar_sha256,
        path_profile_cbor_bytes,
        working_directory_relative_path,
        primary_source_relative_path,
    )
    if not base[3]:
        raise _fail("expected collector GNU build-ID descriptor must be nonempty")

    # These two validators live with the root-free wire because they enforce
    # its exact byte-size limits.  This local import avoids a module cycle;
    # it executes only after both modules have completed import.
    from .capture_v2_native_handoff_v1 import _validate_harness, _validate_public_rows

    try:
        rows = _validate_public_rows(
            public_file_rows_cbor_bytes,
            base[9],
            base[4],
        )
    except EIRPrebindingError as exc:
        raise _fail(
            "public rows do not satisfy the frozen runtime topology projection"
        ) from exc
    try:
        argv = validate_requested_driver_argv_v1(
            argv_grammar_version=base[5],
            argv_grammar_sha256=base[6],
            path_profile_cbor_bytes=base[7],
            working_directory_relative_path=base[8],
            primary_source_relative_path=base[9],
            requested_argv=requested_argv,
        )
    except EIRPrebindingError as exc:
        raise _fail("requested_argv violates CLANG16_CAPTURE_PROFILE_GRAMMAR_V1") from exc
    if type(harness_expectations) not in (list, tuple):
        raise _fail("harness expectations must be an array")
    try:
        harness = _validate_harness(
            [list(item) for item in harness_expectations]
        )
    except EIRPrebindingError as exc:
        raise _fail("harness expectations violate the frozen schema") from exc
    return [
        PROTOCOL_ID,
        VALIDATED_PRELAUNCH_EXPECTATIONS_VERSION_V2,
        RAW_PRELAUNCH_REQUEST_VERSION_V1,
        *base[2:],
        rows,
        list(argv),
        [list(item) for item in harness],
    ]


def _artifact_root_v2(canonical_cbor_bytes: bytes) -> bytes:
    return sha256(
        VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2 + canonical_cbor_bytes
    ).digest()


class ValidatedPrelaunchExpectationsV2:
    """The sole rooted, immutable production prelaunch commitment."""

    __slots__ = ("__canonical_cbor_bytes", "__root", "__value")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("ValidatedPrelaunchExpectationsV2 cannot be subclassed")

    def __init__(
        self,
        authority: _PrelaunchValidatorAuthority,
        canonical_cbor_bytes: bytes,
        root: bytes,
        value: list[Any],
    ) -> None:
        if authority is not _PRELAUNCH_VALIDATOR_AUTHORITY:
            raise TypeError(
                "ValidatedPrelaunchExpectationsV2 is created only by the prelaunch validator"
            )
        object.__setattr__(self, "_ValidatedPrelaunchExpectationsV2__canonical_cbor_bytes", bytes(canonical_cbor_bytes))
        object.__setattr__(self, "_ValidatedPrelaunchExpectationsV2__root", bytes(root))
        object.__setattr__(
            self,
            "_ValidatedPrelaunchExpectationsV2__value",
            (
                value[3], value[4], bytes(value[5]), value[6], bytes(value[7]),
                bytes(value[8]), value[9], value[10], bytes(value[11]),
                tuple(value[12]),
                tuple((int(length), bytes(digest), bytes(build_id)) for length, digest, build_id in value[13]),
            ),
        )

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ValidatedPrelaunchExpectationsV2 is immutable")

    @property
    def canonical_cbor_bytes(self) -> bytes:
        return self.__canonical_cbor_bytes

    @property
    def validated_prelaunch_expectations_root(self) -> bytes:
        return self.__root

    @property
    def collector_profile_build_label_text(self) -> str:
        return self.__value[0]

    @property
    def expected_collector_gnu_build_id_descriptor_bytes(self) -> bytes:
        return self.__value[1]

    @property
    def collector_profile_cbor_bytes(self) -> bytes:
        return self.__value[2]

    @property
    def argv_grammar_version(self) -> int:
        return self.__value[3]

    @property
    def argv_grammar_sha256(self) -> bytes:
        return self.__value[4]

    @property
    def path_profile_cbor_bytes(self) -> bytes:
        return self.__value[5]

    @property
    def working_directory_relative_path(self) -> str:
        return self.__value[6]

    @property
    def primary_source_relative_path(self) -> str:
        return self.__value[7]

    @property
    def public_file_rows_cbor_bytes(self) -> bytes:
        return self.__value[8]

    @property
    def requested_argv(self) -> tuple[str, ...]:
        return self.__value[9]

    @property
    def harness_expectations(self) -> tuple[tuple[int, bytes, bytes], ...]:
        return self.__value[10]


def freeze_validated_prelaunch_expectations_v2(
    *,
    collector_profile_build_label_text: str,
    expected_collector_gnu_build_id_descriptor_bytes: bytes,
    collector_profile_cbor_bytes: bytes,
    argv_grammar_version: int,
    argv_grammar_sha256: bytes,
    path_profile_cbor_bytes: bytes,
    working_directory_relative_path: str,
    primary_source_relative_path: str,
    public_file_rows_cbor_bytes: bytes,
    requested_argv: Any,
    harness_expectations: Any,
) -> ValidatedPrelaunchExpectationsV2:
    """Freeze every raw semantic leaf before any raw wire is constructed."""

    value = _validated_value_v2(
        collector_profile_build_label_text,
        expected_collector_gnu_build_id_descriptor_bytes,
        collector_profile_cbor_bytes,
        argv_grammar_version,
        argv_grammar_sha256,
        path_profile_cbor_bytes,
        working_directory_relative_path,
        primary_source_relative_path,
        public_file_rows_cbor_bytes,
        requested_argv,
        harness_expectations,
    )
    canonical = eir_canonical_cbor_encode(value)
    return ValidatedPrelaunchExpectationsV2(
        _PRELAUNCH_VALIDATOR_AUTHORITY,
        canonical,
        _artifact_root_v2(canonical),
        value,
    )


def _validate_frozen_prelaunch_expectations_v2(artifact: Any) -> list[Any]:
    if type(artifact) is not ValidatedPrelaunchExpectationsV2:
        raise _fail("production assembly requires the V2 prelaunch artifact")
    try:
        decoded = eir_canonical_cbor_decode(artifact.canonical_cbor_bytes)
    except EIRPrebindingError as exc:
        raise _fail("V2 prelaunch artifact bytes are not canonical arrays-only CBOR") from exc
    if (
        type(decoded) is not list
        or len(decoded) != 14
        or decoded[:3]
        != [
            PROTOCOL_ID,
            VALIDATED_PRELAUNCH_EXPECTATIONS_VERSION_V2,
            RAW_PRELAUNCH_REQUEST_VERSION_V1,
        ]
    ):
        raise _fail("prelaunch artifact is not the exact rooted V2 schema")
    value = _validated_value_v2(*decoded[3:])
    if eir_canonical_cbor_encode(value) != artifact.canonical_cbor_bytes:
        raise _fail("V2 prelaunch artifact bytes are not byte-canonical")
    if _artifact_root_v2(artifact.canonical_cbor_bytes) != artifact.validated_prelaunch_expectations_root:
        raise _fail("V2 prelaunch artifact root does not recompute")
    stored = [
        value[3], value[4], value[5], value[6], value[7], value[8],
        value[9], value[10], value[11], list(value[12]), [list(item) for item in value[13]],
    ]
    typed = [
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
    if stored != typed:
        raise _fail("V2 prelaunch typed fields differ from canonical bytes")
    return value


__all__ = [
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "HOLDOUT_ACCESS_AUTHORITY",
    "MAXIMUM_GNU_BUILD_ID_DESCRIPTOR_BYTES_V1",
    "MAXIMUM_PROFILE_BUILD_LABEL_BYTES_V1",
    "PERMIT_AUTHORITY",
    "PRELAUNCH_EXPECTATIONS_INVALID",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "PrelaunchExpectationsError",
    "SEALED_HOLDOUT_ACCESS_AUTHORITY",
    "UPLOAD_AUTHORITY",
    "VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2",
    "VALIDATED_PRELAUNCH_EXPECTATIONS_VERSION_V2",
    "ValidatedPrelaunchExpectationsV2",
    "freeze_validated_prelaunch_expectations_v2",
]
