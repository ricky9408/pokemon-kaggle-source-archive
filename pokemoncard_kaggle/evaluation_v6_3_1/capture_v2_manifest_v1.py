"""Frozen, zero-authority Capture V2 manifest derivation.

This module implements only the private manifest-verification layer consumed by
the production Bridge V3 assembler and bound by
``V631302_NAMESPACE_IDENTITY_PATH_PROFILE_AND_CAPTURE_GRAMMAR_ADDENDUM_1``.
It never reads the host filesystem.  Exact receipt argv, sealed namespace
leaves, and actual-open observations are its only inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import posixpath
from typing import Any

from .eir_prebinding import (
    EIRPrebindingError,
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
)


PROTOCOL_ID = 631302
CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1 = 1

FORM_COMMAND = 1
FORM_FLAG = 2
FORM_SEPARATE = 3
FORM_JOINED = 4
FORM_POSITIONAL = 5

SEM_CONTROL = 1
SEM_SCALAR = 2
SEM_SEARCH_DIRECTORY = 3
SEM_INPUT_FILE_REQUIRED = 4
SEM_MAIN_FILE_BASENAME = 5
SEM_COMMAND_PATH = 6

DRIVER_PHASE = 1
CC1_PHASE = 2
REGULAR_FILE_TYPE = 1

CAPTURE_V2_MANIFEST_DERIVATION_FAILED = "CAPTURE_V2_MANIFEST_DERIVATION_FAILED"
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


class CaptureV2ManifestDerivationError(EIRPrebindingError):
    """Exact bridge leaves do not support one deterministic manifest."""

    def __init__(self, message: str) -> None:
        super().__init__(CAPTURE_V2_MANIFEST_DERIVATION_FAILED, message)


def _fail(message: str) -> CaptureV2ManifestDerivationError:
    return CaptureV2ManifestDerivationError(message)


def _rule(
    identifier: int,
    form: int,
    spelling: str,
    semantic: int,
    minimum: int,
    maximum: int,
    allowed_values: list[str] | None = None,
) -> list[Any]:
    return [
        identifier,
        form,
        spelling,
        semantic,
        minimum,
        maximum,
        [] if allowed_values is None else allowed_values,
    ]


_DRIVER_RULES = [
    _rule(1, FORM_COMMAND, "", SEM_COMMAND_PATH, 1, 1, ["clang-tool"]),
    _rule(2, FORM_POSITIONAL, "", SEM_INPUT_FILE_REQUIRED, 1, 1),
    _rule(3, FORM_FLAG, "-fsyntax-only", SEM_CONTROL, 1, 1),
    _rule(4, FORM_FLAG, "-nostdinc", SEM_CONTROL, 1, 1),
    _rule(5, FORM_FLAG, "--no-default-config", SEM_CONTROL, 1, 1),
    _rule(6, FORM_SEPARATE, "-I", SEM_SEARCH_DIRECTORY, 1, 64),
    _rule(7, FORM_SEPARATE, "-resource-dir", SEM_SEARCH_DIRECTORY, 0, 1),
    _rule(8, FORM_JOINED, "-resource-dir=", SEM_SEARCH_DIRECTORY, 0, 1),
    _rule(9, FORM_JOINED, "-std=", SEM_SCALAR, 1, 1, ["c++20"]),
]

_CC1_RULES = [
    _rule(1, FORM_FLAG, "-cc1", SEM_CONTROL, 1, 1),
    _rule(2, FORM_POSITIONAL, "", SEM_INPUT_FILE_REQUIRED, 1, 1),
    _rule(3, FORM_SEPARATE, "-I", SEM_SEARCH_DIRECTORY, 1, 64),
    _rule(4, FORM_SEPARATE, "-internal-isystem", SEM_SEARCH_DIRECTORY, 0, 64),
    _rule(5, FORM_SEPARATE, "-internal-externc-isystem", SEM_SEARCH_DIRECTORY, 0, 64),
    _rule(6, FORM_SEPARATE, "-resource-dir", SEM_SEARCH_DIRECTORY, 0, 1),
    _rule(7, FORM_JOINED, "-resource-dir=", SEM_SEARCH_DIRECTORY, 0, 1),
    _rule(8, FORM_JOINED, "-std=", SEM_SCALAR, 1, 1, ["c++20"]),
    _rule(9, FORM_SEPARATE, "-main-file-name", SEM_MAIN_FILE_BASENAME, 1, 1),
    _rule(10, FORM_SEPARATE, "-x", SEM_SCALAR, 1, 1, ["c++"]),
    _rule(11, FORM_SEPARATE, "-triple", SEM_SCALAR, 1, 1, ["x86_64-unknown-linux-gnu"]),
    _rule(12, FORM_FLAG, "-fsyntax-only", SEM_CONTROL, 1, 1),
    _rule(13, FORM_FLAG, "-disable-free", SEM_CONTROL, 1, 1),
    _rule(14, FORM_FLAG, "-clear-ast-before-backend", SEM_CONTROL, 1, 1),
    _rule(15, FORM_FLAG, "-disable-llvm-verifier", SEM_CONTROL, 1, 1),
    _rule(16, FORM_FLAG, "-discard-value-names", SEM_CONTROL, 1, 1),
    _rule(17, FORM_SEPARATE, "-mrelocation-model", SEM_SCALAR, 1, 1, ["pic"]),
    _rule(18, FORM_SEPARATE, "-pic-level", SEM_SCALAR, 1, 1, ["2"]),
    _rule(19, FORM_FLAG, "-pic-is-pie", SEM_CONTROL, 1, 1),
    _rule(20, FORM_FLAG, "-mframe-pointer=all", SEM_CONTROL, 1, 1),
    _rule(21, FORM_FLAG, "-fmath-errno", SEM_CONTROL, 1, 1),
    _rule(22, FORM_FLAG, "-ffp-contract=on", SEM_CONTROL, 1, 1),
    _rule(23, FORM_FLAG, "-fno-rounding-math", SEM_CONTROL, 1, 1),
    _rule(24, FORM_FLAG, "-mconstructor-aliases", SEM_CONTROL, 1, 1),
    _rule(25, FORM_FLAG, "-funwind-tables=2", SEM_CONTROL, 1, 1),
    _rule(26, FORM_SEPARATE, "-target-cpu", SEM_SCALAR, 1, 1, ["x86-64"]),
    _rule(27, FORM_SEPARATE, "-tune-cpu", SEM_SCALAR, 1, 1, ["generic"]),
    _rule(
        28,
        FORM_SEPARATE,
        "-mllvm",
        SEM_SCALAR,
        1,
        1,
        ["-treat-scalable-fixed-error-as-warning"],
    ),
    _rule(29, FORM_FLAG, "-debugger-tuning=gdb", SEM_CONTROL, 1, 1),
    _rule(30, FORM_FLAG, "-fcoverage-compilation-dir=/", SEM_CONTROL, 1, 1),
    _rule(31, FORM_FLAG, "-nostdsysteminc", SEM_CONTROL, 1, 1),
    _rule(32, FORM_FLAG, "-nobuiltininc", SEM_CONTROL, 1, 1),
    _rule(33, FORM_FLAG, "-fdeprecated-macro", SEM_CONTROL, 1, 1),
    _rule(34, FORM_FLAG, "-fdebug-compilation-dir=/", SEM_CONTROL, 1, 1),
    _rule(35, FORM_SEPARATE, "-ferror-limit", SEM_SCALAR, 1, 1, ["19"]),
    _rule(36, FORM_FLAG, "-fgnuc-version=4.2.1", SEM_CONTROL, 1, 1),
    _rule(37, FORM_FLAG, "-fno-implicit-modules", SEM_CONTROL, 1, 1),
    _rule(38, FORM_FLAG, "-fcxx-exceptions", SEM_CONTROL, 1, 1),
    _rule(39, FORM_FLAG, "-fexceptions", SEM_CONTROL, 1, 1),
    _rule(40, FORM_FLAG, "-faddrsig", SEM_CONTROL, 1, 1),
    _rule(41, FORM_FLAG, "-D__GCC_HAVE_DWARF2_CFI_ASM=1", SEM_CONTROL, 1, 1),
]

# Rule groups make mutually exclusive spellings explicit.  Each row is
# [minimum_total, maximum_total, rule_ids].
CLANG16_CAPTURE_PROFILE_GRAMMAR_V1 = [
    PROTOCOL_ID,
    CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1,
    [1, "driver", _DRIVER_RULES, [[1, 1, [7, 8]]]],
    [2, "cc1", _CC1_RULES, [[1, 1, [6, 7]]]],
]

CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_CBOR = eir_canonical_cbor_encode(
    CLANG16_CAPTURE_PROFILE_GRAMMAR_V1
)
CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256 = sha256(
    CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_CBOR
).digest()
_PINNED_GRAMMAR_SHA256 = bytes.fromhex(
    "085029058792fedadb7441d733321e961255bf65598b2b54a439cb426db54160"
)
if CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256 != _PINNED_GRAMMAR_SHA256:
    raise RuntimeError("CLANG16_CAPTURE_PROFILE_GRAMMAR_V1 pin changed")


PATH_PROFILE_V2 = [2, "/src", "/work", "/bin"]
PATH_PROFILE_V2_CBOR = eir_canonical_cbor_encode(PATH_PROFILE_V2)


@dataclass(frozen=True)
class PathProfileV2:
    version: int
    source_absolute_prefix: str
    work_absolute_prefix: str
    command_absolute_prefix: str
    namespace_root: str
    working_directory_relative_path: str


@dataclass(frozen=True)
class ParsedArgvV1:
    required_input_paths: frozenset[str]
    search_directory_paths: tuple[str, ...]


@dataclass(frozen=True)
class DerivedInputManifestsV1:
    driver_manifest: list[Any]
    cc1_manifest: list[Any]
    path_profile: PathProfileV2


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


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise _fail(f"{label} must be nonempty NUL-free text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(f"{label} must be valid UTF-8") from exc
    return value


def _bstr(value: Any, label: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise _fail(f"{label} must be a byte string")
    if length is not None and len(value) != length:
        raise _fail(f"{label} must be exactly {length} bytes")
    return value


def _relative_path(value: Any, label: str) -> str:
    path = _text(value, label)
    if path.startswith("/") or "\\" in path:
        raise _fail(f"{label} must be a slash-separated relative path")
    if any(component in ("", ".", "..") for component in path.split("/")):
        raise _fail(f"{label} is not canonical")
    return path


def _canonical_absolute_path(value: Any, label: str) -> str:
    path = _text(value, label)
    if not path.startswith("/") or path == "/" or path.endswith("/") or "\\" in path:
        raise _fail(f"{label} must be a non-root canonical absolute POSIX path")
    if any(component in ("", ".", "..") for component in path[1:].split("/")):
        raise _fail(f"{label} is not canonical")
    return path


def _beneath(path: str, root: str) -> bool:
    if root == "/":
        return path.startswith("/") and path != "/"
    return path.startswith(root + "/")


def _namespace_relative(absolute_path: str, namespace_root: str, label: str) -> str:
    if not _beneath(absolute_path, namespace_root):
        raise _fail(f"{label} escapes the frozen namespace root")
    relative = absolute_path[1:] if namespace_root == "/" else absolute_path[len(namespace_root) + 1 :]
    return _relative_path(relative, label)


def validate_path_profile_v2(
    value: Any,
    working_directory_relative_path: Any,
) -> PathProfileV2:
    profile = _list(value, "PATH_PROFILE_V2", 4)
    if _uint(profile[0], "path profile version") != 2:
        raise _fail("PATH_PROFILE_V1 and other path profiles are rejected")
    if profile != PATH_PROFILE_V2:
        raise _fail("path profile is not the exact frozen PATH_PROFILE_V2")
    source = _canonical_absolute_path(profile[1], "source_absolute_prefix")
    work = _canonical_absolute_path(profile[2], "work_absolute_prefix")
    command = _canonical_absolute_path(profile[3], "command_absolute_prefix")
    namespace_root = "/"
    working = _relative_path(
        working_directory_relative_path, "working_directory_relative_path"
    )
    if "/" + working != work:
        raise _fail("working directory differs from PATH_PROFILE_V2 work prefix")
    return PathProfileV2(
        version=2,
        source_absolute_prefix=source,
        work_absolute_prefix=work,
        command_absolute_prefix=command,
        namespace_root=namespace_root,
        working_directory_relative_path=working,
    )


def validate_path_profile_v1(value: Any, working_directory_absolute: Any) -> PathProfileV2:
    """Retired V1 entrypoint; all new evidence must use PATH_PROFILE_V2."""

    raise _fail("PATH_PROFILE_V1 is retired for new Capture V2 evidence")


def _resolve_argv_path(token: str, profile: PathProfileV2, label: str) -> str:
    value = _text(token, label)
    if "\\" in value:
        raise _fail(f"{label} is not a POSIX path")
    if value.startswith("/"):
        normalized = posixpath.normpath(value)
    else:
        normalized = posixpath.normpath(
            posixpath.join(profile.work_absolute_prefix, value)
        )
    if not normalized.startswith("/"):
        raise _fail(f"{label} did not resolve to an absolute path")
    return _namespace_relative(normalized, profile.namespace_root, label)


def _validate_grammar_artifact() -> dict[int, tuple[list[Any], list[Any]]]:
    raw = CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_CBOR
    try:
        value = eir_canonical_cbor_decode(raw)
    except EIRPrebindingError as exc:
        raise _fail("frozen argv grammar is not canonical CBOR") from exc
    if value != CLANG16_CAPTURE_PROFILE_GRAMMAR_V1 or eir_canonical_cbor_encode(value) != raw:
        raise _fail("frozen argv grammar is not byte-identical")
    artifact = _list(value, "argv grammar artifact", 4)
    if artifact[0:2] != [PROTOCOL_ID, CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1]:
        raise _fail("frozen argv grammar header is invalid")
    phases: dict[int, tuple[list[Any], list[Any]]] = {}
    for phase_value in artifact[2:]:
        phase = _list(phase_value, "argv grammar phase", 4)
        phase_id = _uint(phase[0], "argv grammar phase id", positive=True)
        expected_name = {1: "driver", 2: "cc1"}.get(phase_id)
        if expected_name is None or phase[1] != expected_name or phase_id in phases:
            raise _fail("argv grammar phase identity is invalid")
        rules = _list(phase[2], f"{expected_name} grammar rules")
        groups = _list(phase[3], f"{expected_name} grammar groups")
        identifiers: set[int] = set()
        signatures: set[tuple[int, str]] = set()
        for index, rule_value in enumerate(rules):
            rule = _list(rule_value, f"{expected_name} rule[{index}]", 7)
            identifier = _uint(rule[0], "rule identifier", positive=True)
            form = _uint(rule[1], "rule form", positive=True)
            spelling = rule[2]
            if type(spelling) is not str or "\x00" in spelling:
                raise _fail("rule spelling must be NUL-free text")
            semantic = _uint(rule[3], "rule semantic", positive=True)
            minimum = _uint(rule[4], "rule minimum")
            maximum = _uint(rule[5], "rule maximum")
            allowed = _list(rule[6], "rule allowed values")
            if (
                identifier != index + 1
                or identifier in identifiers
                or form not in range(FORM_COMMAND, FORM_POSITIONAL + 1)
                or semantic not in range(SEM_CONTROL, SEM_COMMAND_PATH + 1)
                or minimum > maximum
                or maximum > 64
                or (form in (FORM_COMMAND, FORM_POSITIONAL) and spelling != "")
                or (form not in (FORM_COMMAND, FORM_POSITIONAL) and not spelling)
                or (form in (FORM_FLAG, FORM_SEPARATE, FORM_JOINED) and not spelling.startswith("-"))
                or (form == FORM_JOINED and not spelling.endswith("="))
                or (form == FORM_FLAG and allowed)
                or (semantic in (SEM_CONTROL, SEM_INPUT_FILE_REQUIRED, SEM_MAIN_FILE_BASENAME) and allowed)
            ):
                raise _fail("argv grammar rule is invalid")
            for allowed_index, item in enumerate(allowed):
                _text(item, f"rule allowed_values[{allowed_index}]")
            signature = (form, spelling)
            if signature in signatures:
                raise _fail("argv grammar contains duplicate rule signatures")
            identifiers.add(identifier)
            signatures.add(signature)
        for group_value in groups:
            group = _list(group_value, "argv grammar group", 3)
            minimum = _uint(group[0], "group minimum")
            maximum = _uint(group[1], "group maximum")
            members = _list(group[2], "group rule identifiers")
            if minimum > maximum or not members:
                raise _fail("argv grammar group bounds are invalid")
            previous = 0
            for member in members:
                identifier = _uint(member, "group rule identifier", positive=True)
                if identifier not in identifiers or identifier <= previous:
                    raise _fail("argv grammar group identifiers are invalid")
                previous = identifier
        phases[phase_id] = (rules, groups)
    if set(phases) != {1, 2}:
        raise _fail("argv grammar lacks an exact driver/cc1 pair")
    return phases


def validate_argv_grammar_pin(version: Any, digest: Any) -> None:
    if _uint(version, "argv_grammar_version") != CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1:
        raise _fail("argv grammar version is not the frozen V1")
    if _bstr(digest, "argv_grammar_sha256", 32) != CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256:
        raise _fail("argv grammar hash is not the frozen V1 artifact")
    _validate_grammar_artifact()


def validate_requested_driver_argv_v1(
    *,
    argv_grammar_version: Any,
    argv_grammar_sha256: Any,
    path_profile_cbor_bytes: Any,
    working_directory_relative_path: Any,
    primary_source_relative_path: Any,
    requested_argv: Any,
) -> tuple[str, ...]:
    """Validate the committed inner Clang driver argv, not a collector launch.

    Amendment 5 makes RAW_PRELAUNCH_REQUEST_V1 field 11 the exact compiler
    driver invocation.  This narrow helper keeps that semantic check beside
    the frozen grammar parser while leaving launcher derivation to the
    prelaunch handoff boundary.
    """

    validate_argv_grammar_pin(argv_grammar_version, argv_grammar_sha256)
    if type(path_profile_cbor_bytes) is not bytes:
        raise _fail("path profile bytes must be immutable")
    path_profile = eir_canonical_cbor_decode(path_profile_cbor_bytes)
    if eir_canonical_cbor_encode(path_profile) != path_profile_cbor_bytes:
        raise _fail("path profile bytes are not canonical")
    profile = validate_path_profile_v2(
        path_profile,
        working_directory_relative_path,
    )
    primary = _relative_path(primary_source_relative_path, "primary_source")
    if primary != "src/Export.cpp":
        raise _fail("primary source is not the frozen Export.cpp path")
    if type(requested_argv) not in (list, tuple):
        raise _fail("requested_argv must be an array")
    argv = list(requested_argv)
    parsed = tuple(_text(token, f"requested_argv[{index}]") for index, token in enumerate(argv))
    if not parsed or parsed[0] != "/bin/clang-tool":
        raise _fail("requested_argv[0] is not the frozen Clang driver")
    _parse_argv(list(parsed), DRIVER_PHASE, profile, primary)
    return parsed


def _rule_matches(rule: list[Any], token: str) -> tuple[bool, str | None]:
    form, spelling = rule[1], rule[2]
    if form == FORM_FLAG:
        return token == spelling, None
    if form == FORM_SEPARATE:
        return token == spelling, None
    if form == FORM_JOINED:
        return token.startswith(spelling) and len(token) > len(spelling), token[len(spelling) :]
    if form == FORM_POSITIONAL:
        return not token.startswith("-"), token
    return False, None


def _parse_argv(
    argv_value: Any,
    phase_id: int,
    profile: PathProfileV2,
    primary_source_relative_path: str,
) -> ParsedArgvV1:
    argv = _list(argv_value, "driver argv" if phase_id == 1 else "cc1 argv")
    if not argv:
        raise _fail("argv must be nonempty")
    tokens = [_text(item, f"argv[{index}]") for index, item in enumerate(argv)]
    if any(token.startswith("@") for token in tokens):
        raise _fail("response files are prohibited by capture grammar V1")
    rules, groups = _validate_grammar_artifact()[phase_id]
    counts = {rule[0]: 0 for rule in rules}
    required_inputs: set[str] = set()
    search_directories: list[str] = []

    start = 0
    if phase_id == 1:
        command_rule = next(rule for rule in rules if rule[1] == FORM_COMMAND)
        command = _canonical_absolute_path(tokens[0], "driver command")
        if not _beneath(command, profile.command_absolute_prefix):
            raise _fail("driver command is outside command_absolute_prefix")
        if posixpath.basename(command) not in command_rule[6]:
            raise _fail("driver command basename is not frozen by grammar V1")
        counts[command_rule[0]] += 1
        start = 1
    elif tokens[0] != "-cc1":
        raise _fail("cc1 argv must begin with exact -cc1")

    index = start
    basename_claims: list[str] = []
    while index < len(tokens):
        token = tokens[index]
        matches: list[tuple[list[Any], str | None]] = []
        for rule in rules:
            if rule[1] == FORM_COMMAND:
                continue
            matched, joined_value = _rule_matches(rule, token)
            if matched:
                matches.append((rule, joined_value))
        if len(matches) != 1:
            raise _fail(f"argv token has no unique frozen grammar meaning: {token!r}")
        rule, value = matches[0]
        form, semantic = rule[1], rule[3]
        if form == FORM_SEPARATE:
            if index + 1 >= len(tokens):
                raise _fail(f"argv option lacks its required value: {token!r}")
            index += 1
            value = tokens[index]
        elif form == FORM_FLAG:
            value = None
        elif form == FORM_POSITIONAL:
            value = token
        if counts[rule[0]] >= rule[5]:
            raise _fail(f"argv option exceeds its frozen multiplicity: {token!r}")
        counts[rule[0]] += 1
        if value is not None:
            if rule[6] and value not in rule[6]:
                raise _fail(f"argv scalar value is outside the frozen profile: {value!r}")
            if semantic == SEM_INPUT_FILE_REQUIRED:
                required_inputs.add(
                    _resolve_argv_path(value, profile, "required argv input")
                )
            elif semantic == SEM_SEARCH_DIRECTORY:
                resolved = _resolve_argv_path(value, profile, "argv search directory")
                allowed_prefixes = (
                    profile.source_absolute_prefix,
                    profile.work_absolute_prefix,
                    profile.command_absolute_prefix,
                    "/lib",
                )
                if not any(
                    resolved == prefix[1:] or resolved.startswith(prefix[1:] + "/")
                    for prefix in allowed_prefixes
                ):
                    raise _fail("argv search directory is outside PATH_PROFILE_V2")
                search_directories.append(resolved)
            elif semantic == SEM_MAIN_FILE_BASENAME:
                basename_claims.append(value)
        index += 1

    for rule in rules:
        count = counts[rule[0]]
        if count < rule[4] or count > rule[5]:
            raise _fail(f"argv rule {rule[0]} violates frozen multiplicity")
    for minimum, maximum, identifiers in groups:
        total = sum(counts[identifier] for identifier in identifiers)
        if total < minimum or total > maximum:
            raise _fail("argv mutually exclusive spelling group is invalid")
    if required_inputs != {primary_source_relative_path}:
        raise _fail("argv required inputs are not exactly the committed primary source")
    if phase_id == 2 and basename_claims != [posixpath.basename(primary_source_relative_path)]:
        raise _fail("cc1 -main-file-name differs from the primary source basename")
    return ParsedArgvV1(
        required_input_paths=frozenset(required_inputs),
        search_directory_paths=tuple(search_directories),
    )


def _linux_device_pair(device: int) -> tuple[int, int]:
    # Linux glibc gnu_dev_major/gnu_dev_minor, evaluated without host os.major
    # so Darwin-hosted verification cannot reinterpret a Linux dev_t value.
    major = ((device >> 8) & 0xFFF) | ((device >> 32) & 0xFFFFF000)
    minor = (device & 0xFF) | ((device >> 12) & 0xFFFFFF00)
    return major, minor


def _validate_namespace_identities(
    public_file_rows_value: Any,
    namespace_identity_rows_value: Any,
) -> tuple[dict[str, list[Any]], dict[str, list[Any]]]:
    public_rows = _list(public_file_rows_value, "public_file_rows")
    identity_rows = _list(namespace_identity_rows_value, "namespace_identity_rows")
    if len(public_rows) != len(identity_rows) or not public_rows:
        raise _fail("namespace identity coverage must be exactly one-to-one")
    public_by_path: dict[str, list[Any]] = {}
    identity_by_path: dict[str, list[Any]] = {}
    identities: set[tuple[int, int, int]] = set()
    previous_path_bytes: bytes | None = None
    for index, (public_value, identity_value) in enumerate(zip(public_rows, identity_rows)):
        public = _list(public_value, f"public_file_rows[{index}]", 5)
        path = _relative_path(public[0], f"public_file_rows[{index}].path")
        _list(public[1], f"public_file_rows[{index}].roles")
        mode = _uint(public[2], f"public_file_rows[{index}].mode")
        length = _uint(public[3], f"public_file_rows[{index}].length")
        digest = _bstr(public[4], f"public_file_rows[{index}].sha256", 32)
        identity = _list(identity_value, f"namespace_identity_rows[{index}]", 7)
        identity_path = _relative_path(
            identity[0], f"namespace_identity_rows[{index}].path"
        )
        device = _list(identity[1], f"namespace_identity_rows[{index}].device", 2)
        device_major = _uint(device[0], "namespace device major")
        device_minor = _uint(device[1], "namespace device minor")
        inode = _uint(identity[2], "namespace inode", positive=True)
        file_type = _uint(identity[3], "namespace file type", positive=True)
        identity_mode = _uint(identity[4], "namespace normalized mode")
        identity_length = _uint(identity[5], "namespace byte length")
        identity_digest = _bstr(identity[6], "namespace sha256", 32)
        path_bytes = identity_path.encode("utf-8")
        if previous_path_bytes is not None and path_bytes <= previous_path_bytes:
            raise _fail("namespace identity rows are not strictly UTF-8 path sorted")
        previous_path_bytes = path_bytes
        object_identity = (device_major, device_minor, inode)
        if object_identity in identities:
            raise _fail("namespace identity rows contain a device/inode alias")
        identities.add(object_identity)
        if (
            identity_path != path
            or file_type != REGULAR_FILE_TYPE
            or identity_mode != mode
            or identity_length != length
            or identity_digest != digest
        ):
            raise _fail("namespace identity differs from its public file row")
        if path in public_by_path:
            raise _fail("namespace file path is duplicated")
        public_by_path[path] = public
        identity_by_path[path] = identity
    return public_by_path, identity_by_path


def _phase_manifest_rows(
    actual_open_rows_value: Any,
    public_rows: dict[str, list[Any]],
    identity_rows: dict[str, list[Any]],
) -> dict[int, list[list[Any]]]:
    actual_open_rows = _list(actual_open_rows_value, "actual_open_rows")
    phase_paths: dict[int, dict[str, list[Any]]] = {DRIVER_PHASE: {}, CC1_PHASE: {}}
    previous_sequence = -1
    previous_phase = -1
    for index, row_value in enumerate(actual_open_rows):
        row = _list(row_value, f"actual_open_rows[{index}]", 9)
        sequence = _uint(row[0], "actual open sequence")
        phase = _uint(row[1], "actual open phase")
        path = _relative_path(row[2], "actual open path")
        _uint(row[3], "actual open flags")
        raw_device = _uint(row[4], "actual open device")
        inode = _uint(row[5], "actual open inode", positive=True)
        mode = _uint(row[6], "actual open normalized mode")
        length = _uint(row[7], "actual open length")
        digest = _bstr(row[8], "actual open sha256", 32)
        if sequence != previous_sequence + 1 or phase not in range(4) or phase < previous_phase:
            raise _fail("actual-open sequence or phase order is invalid")
        previous_sequence = sequence
        previous_phase = phase
        public = public_rows.get(path)
        identity = identity_rows.get(path)
        if public is None or identity is None:
            raise _fail("actual open lacks one exact namespace identity")
        expected_device = tuple(identity[1])
        if (
            _linux_device_pair(raw_device) != expected_device
            or inode != identity[2]
            or mode != identity[4]
            or length != public[3]
            or digest != public[4]
        ):
            raise _fail("actual open differs from its sealed namespace identity")
        if phase in phase_paths:
            phase_paths[phase][path] = [path, length, digest]
    return {
        phase: sorted(rows.values(), key=eir_canonical_cbor_encode)
        for phase, rows in phase_paths.items()
    }


def derive_input_manifests_v1(
    *,
    argv_grammar_version: Any,
    argv_grammar_sha256: Any,
    working_directory_relative_path: Any,
    primary_source_relative_path: Any,
    path_profile: Any,
    public_file_rows: Any,
    namespace_identity_rows: Any,
    driver_argv: Any,
    cc1_argv: Any,
    actual_open_rows: Any,
) -> DerivedInputManifestsV1:
    """Derive both public manifests from exact private bridge leaves."""

    validate_argv_grammar_pin(argv_grammar_version, argv_grammar_sha256)
    profile = validate_path_profile_v2(path_profile, working_directory_relative_path)
    primary = _relative_path(primary_source_relative_path, "primary_source")
    primary_absolute = "/" + primary
    if not _beneath(primary_absolute, profile.source_absolute_prefix):
        raise _fail("primary source is outside source_absolute_prefix")
    public_rows, identity_rows = _validate_namespace_identities(
        public_file_rows, namespace_identity_rows
    )
    if primary not in public_rows:
        raise _fail("primary source is absent from the namespace")
    driver_parsed = _parse_argv(driver_argv, 1, profile, primary)
    cc1_parsed = _parse_argv(cc1_argv, 2, profile, primary)
    phase_rows = _phase_manifest_rows(actual_open_rows, public_rows, identity_rows)
    for label, parsed, phase in (
        ("driver", driver_parsed, DRIVER_PHASE),
        ("cc1", cc1_parsed, CC1_PHASE),
    ):
        opened = {row[0] for row in phase_rows[phase]}
        if not parsed.required_input_paths.issubset(opened):
            raise _fail(f"{label} required argv input was not opened in its exact phase")
        if primary not in opened:
            raise _fail(f"{label} manifest does not contain the primary source")
    return DerivedInputManifestsV1(
        driver_manifest=[list(driver_argv), phase_rows[DRIVER_PHASE]],
        cc1_manifest=[list(cc1_argv), phase_rows[CC1_PHASE]],
        path_profile=profile,
    )


__all__ = [
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "CAPTURE_V2_MANIFEST_DERIVATION_FAILED",
    "CLANG16_CAPTURE_PROFILE_GRAMMAR_V1",
    "CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_CBOR",
    "CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256",
    "CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1",
    "CaptureV2ManifestDerivationError",
    "DerivedInputManifestsV1",
    "HOLDOUT_ACCESS_AUTHORITY",
    "PERMIT_AUTHORITY",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "SEALED_HOLDOUT_ACCESS_AUTHORITY",
    "UPLOAD_AUTHORITY",
    "PATH_PROFILE_V2",
    "PATH_PROFILE_V2_CBOR",
    "PathProfileV2",
    "derive_input_manifests_v1",
    "validate_argv_grammar_pin",
    "validate_requested_driver_argv_v1",
    "validate_path_profile_v2",
    "validate_path_profile_v1",
]
