from __future__ import annotations

from .m0_diagnostic_primitives import (
    M0PrimitiveError,
    bstr32 as primitive_bstr32,
    canonical_cbor_decode,
    canonical_cbor_encode,
    construct_key,
    definition_instance_key_v2,
    qtid_ascii_v1,
    sha256_digest,
    subject_key,
    text as primitive_text,
    uint as primitive_uint,
)


PROTOCOL_ID = 631302
WIRE_VERSION = 1
DIAGNOSTIC_CENSUS_V1 = "DIAGNOSTIC_CENSUS_V1"

M0_DIAGNOSTIC_INVENTORY_INCOMPLETE = "M0_DIAGNOSTIC_INVENTORY_INCOMPLETE"
M0_TEMPLATE_EMISSION_STATUS_UNPROVEN = "M0_TEMPLATE_EMISSION_STATUS_UNPROVEN"

CANONICALIZER_NATIVE = 0
CANONICALIZER_PYTHON = 1
REGISTRY_STATUS_PROVISIONAL_DIAGNOSTIC_ONLY = 0
DIAGNOSTIC_TARGET_REGISTRY_DOMAIN = b"V631302_DIAGNOSTIC_TARGET_REGISTRY_V1"
CANONICALIZER_BUNDLE_DOMAIN = b"V631302_CANONICALIZER_BUNDLE_V1"
CANONICALIZER_ENTRY_MODULE_PATH = "evaluation_v6_3_1/m0_diagnostic_census.py"
CANONICALIZER_WORKER_ENTRY_PATH = "worker/v631302_diagnostic_worker_v1.py"
FROZEN_TARGET_DESCRIPTORS_CBOR_SHA256 = bytes.fromhex(
    "4b218e8cc34481efb13065641e563769f71bbf7d8dc1deaa9745bdf81a0553ca"
)

REPRESENTED = 1
NONINSTANTIATED_OR_DISCARDED = 2
UNSUPPORTED = 3

_DISPOSITIONS = frozenset((REPRESENTED, NONINSTANTIATED_OR_DISCARDED, UNSUPPORTED))
_RUNTIME_CLASSES = frozenset((1, 2, 3, 4, 5))
_FAILURE_CODE = M0_DIAGNOSTIC_INVENTORY_INCOMPLETE
SOURCE_DEFINITION_INVENTORY = 1
TU_RUNTIME_INVENTORY = 2
DEFINITION_INVOCATION_INVENTORY = 3


M0DiagnosticCensusError = type(
    "M0DiagnosticCensusError",
    (ValueError,),
    {"code": M0_DIAGNOSTIC_INVENTORY_INCOMPLETE},
)
_M0TemplateEmissionError = type(
    "M0TemplateEmissionError",
    (M0DiagnosticCensusError,),
    {"code": M0_TEMPLATE_EMISSION_STATUS_UNPROVEN},
)


def _domain_code(value):
    if type(value) is not int or value not in (1, 2, 3):
        raise M0PrimitiveError("subject domain code is invalid")
    return value


def _struct(message: str) -> M0DiagnosticCensusError:
    return M0DiagnosticCensusError(message)


def _template(message: str) -> M0DiagnosticCensusError:
    return _M0TemplateEmissionError(message)


def _array(value: Any, label: str) -> Sequence[Any]:
    if type(value) not in (list, tuple):
        raise _struct(label + " must be an array")
    return value


def _uint(value: Any, bits: int, label: str) -> int:
    try:
        return primitive_uint(value, bits, label)
    except M0PrimitiveError as exc:
        raise _struct(str(exc)) from exc


def _bit(value: Any, label: str) -> int:
    if type(value) is not int or value not in (0, 1):
        raise _struct(label + " must be the unsigned integer 0 or 1")
    return value


def _text(value: Any, label: str) -> str:
    try:
        return primitive_text(value, label)
    except M0PrimitiveError as exc:
        raise _struct(str(exc)) from exc


def _bstr32(value: Any, label: str) -> bytes:
    try:
        return primitive_bstr32(value, label)
    except M0PrimitiveError as exc:
        raise _struct(str(exc)) from exc


def _wire(value: Any) -> Any:
    """Convert accepted tuple-backed arrays to lists and reject maps/types."""

    if type(value) in (list, tuple):
        return [_wire(item) for item in value]
    if type(value) is dict:
        raise _struct("maps are forbidden by DIAGNOSTIC_CENSUS_V1")
    if type(value) is bool:
        raise _struct("CBOR Boolean values are forbidden by DIAGNOSTIC_CENSUS_V1")
    if type(value) in (str, bytes, int):
        return value
    raise _struct("unsupported value type")


def _encoded(value: Any) -> bytes:
    try:
        return canonical_cbor_encode(_wire(value))
    except (M0PrimitiveError, M0DiagnosticCensusError) as exc:
        raise _struct("value cannot be canonically encoded") from exc


def _bundle_path(value: Any, label: str) -> str:
    path = _text(value, label)
    parts = path.split("/")
    if path.startswith("/") or "\\" in path or any([part in ("", ".", "..") for part in parts]):
        raise _struct(label + " is not a normalized relative bundle path")
    return path


def _bundle_manifest(value: Any) -> list[Any]:
    row = _array(value, "canonicalizer_bundle_manifest")
    if len(row) != 3:
        raise _struct("canonicalizer bundle manifest has the wrong width")
    version = _uint(row[0], 16, "canonicalizer bundle manifest version")
    if version != 1:
        raise _struct("canonicalizer bundle manifest version is invalid")
    entry_path = _bundle_path(row[1], "canonicalizer entry_module_path")
    if entry_path != CANONICALIZER_ENTRY_MODULE_PATH:
        raise _struct("canonicalizer entry module is not the frozen entry point")
    files: list[list[Any]] = []
    path_bytes: list[bytes] = []
    for item in _array(row[2], "canonicalizer bundle_files"):
        file_row = _array(item, "canonicalizer bundle_file")
        if len(file_row) != 3:
            raise _struct("canonicalizer bundle file has the wrong width")
        relative_path = _bundle_path(file_row[0], "canonicalizer bundle relative_path")
        files.append(
            [
                relative_path,
                _uint(file_row[1], 64, "canonicalizer bundle byte_length"),
                _bstr32(file_row[2], "canonicalizer bundle file sha256"),
            ]
        )
        path_bytes.append(relative_path.encode("utf-8"))
    if not files:
        raise _struct("canonicalizer bundle has no files")
    if path_bytes != sorted(set(path_bytes)):
        raise _struct("canonicalizer bundle paths are not strictly UTF-8-byte ordered")
    if entry_path not in {file_row[0] for file_row in files}:
        raise _struct("canonicalizer entry module is absent from the bundle")
    return [version, entry_path, files]


def _bundle_root(manifest: list[Any]) -> bytes:
    return sha256_digest(
        canonical_cbor_encode(
            [
                CANONICALIZER_BUNDLE_DOMAIN,
                PROTOCOL_ID,
                WIRE_VERSION,
                CANONICALIZER_PYTHON,
                manifest,
            ]
        )
    )


def _interpreter_pin(value: Any) -> list[Any]:
    row = _array(value, "interpreter_pin")
    if len(row) != 7:
        raise _struct("interpreter_pin has the wrong width")
    implementation_code = _uint(row[0], 8, "interpreter implementation_code")
    locator_code = _uint(row[1], 8, "interpreter executable_locator_code")
    if implementation_code != 1 or locator_code != 1:
        raise _struct("interpreter implementation or locator is not pinned")
    cache_tag = _text(row[3], "interpreter cache_tag")
    if type(row[4]) is not str or "\x00" in row[4]:
        raise _struct("interpreter abi_flags must be NUL-free text")
    try:
        primitive_text(row[4], "interpreter abi_flags", allow_empty=True)
    except M0PrimitiveError as exc:
        raise _struct(str(exc)) from exc
    return [
        implementation_code,
        locator_code,
        _uint(row[2], 64, "interpreter version_hex"),
        cache_tag,
        row[4],
        _uint(row[5], 64, "interpreter executable_byte_length"),
        _bstr32(row[6], "interpreter executable_sha256"),
    ]


def _execution_profile(value: Any, manifest: list[Any]) -> list[Any]:
    row = _array(value, "canonicalizer_execution_profile")
    if len(row) != 8:
        raise _struct("canonicalizer execution profile has the wrong width")
    version = _uint(row[0], 16, "canonicalizer execution profile version")
    worker_path = _bundle_path(row[2], "worker_entry_path")
    worker_sha = _bstr32(row[3], "worker_entry_sha256")
    profile = [
        version,
        _interpreter_pin(row[1]),
        worker_path,
        worker_sha,
        _uint(row[4], 8, "argv_profile_code"),
        _uint(row[5], 8, "environment_profile_code"),
        _uint(row[6], 8, "import_profile_code"),
        _uint(row[7], 8, "framing_profile_code"),
    ]
    if profile[0] != 1 or profile[2] != CANONICALIZER_WORKER_ENTRY_PATH:
        raise _struct("canonicalizer execution profile is not frozen")
    if profile[4:] != [1, 1, 1, 1]:
        raise _struct("canonicalizer execution isolation codes are not frozen")
    worker_rows = [item for item in manifest[2] if item[0] == worker_path]
    if len(worker_rows) != 1 or worker_rows[0][2] != worker_sha:
        raise _struct("worker entry is not exactly bound by the bundle manifest")
    return profile


def _collector_profile(value: Any, bound_profile_cbor: bytes | None) -> list[Any]:
    row = _array(value, "collector_profile")
    if len(row) != 8:
        raise _struct("collector_profile has the wrong width")
    manifest = _bundle_manifest(row[7])
    supplied_root = _bstr32(row[6], "canonicalizer_bundle_root")
    profile = [
        _bstr32(row[0], "collector_binary_sha256"),
        _text(row[1], "collector_build_id"),
        _bstr32(row[2], "clang_binary_sha256"),
        _uint(row[3], 16, "clang_major"),
        _uint(row[4], 8, "canonicalizer_kind"),
        _execution_profile(row[5], manifest),
        supplied_root,
        manifest,
    ]
    if profile[3] != 16:
        raise _struct("collector_profile is not pinned to Clang 16")
    if profile[4] != CANONICALIZER_PYTHON:
        raise _struct("Binding-10 requires the pinned Python canonicalizer")
    if _bundle_root(manifest) != supplied_root:
        raise _struct("canonicalizer bundle root does not match its manifest")
    if bound_profile_cbor is not None:
        if type(bound_profile_cbor) is not bytes:
            raise _struct("bound collector profile is not immutable bytes")
        if canonical_cbor_encode(profile) != bound_profile_cbor:
            raise _struct("collector profile differs from the prelaunch bound bytes")
    return profile


def _distinct_sorted(rows: Iterable[list[Any]], label: str) -> list[list[Any]]:
    materialized = list(rows)
    keyed = [(_encoded(row), row) for row in materialized]
    keys = [key for key, _ in keyed]
    if len(keys) != len(set(keys)):
        raise _struct(label + " contains duplicate rows")
    return [row for _, row in sorted(keyed, key=lambda item: item[0])]


def _subject(domain: int, value: Any, descriptors: Sequence[Sequence[Any]]) -> list[Any]:
    try:
        row = subject_key(domain, value, len(descriptors))
    except M0PrimitiveError as exc:
        raise _struct(str(exc)) from exc
    if domain == SOURCE_DEFINITION_INVENTORY:
        return row
    semantic = row if domain == TU_RUNTIME_INVENTORY else row[2]
    raw_targets = _array(semantic[4], "target_indices")
    if any([index >= len(descriptors) for index in raw_targets]):
        raise _struct("target index is outside the provisional registry")
    try:
        qtid_ascii_v1(semantic[2])
    except Exception as exc:
        raise _struct("subject raw_qual_type cannot produce Binding-3 identity") from exc
    if domain == DEFINITION_INVOCATION_INVENTORY:
        for index in raw_targets:
            descriptor = descriptors[index]
            if descriptor[1] != semantic[1] or descriptor[2] != semantic[2]:
                raise _struct("definition target identity disagrees with its frozen descriptor")
    return row


def _construct(value: Any) -> list[Any]:
    try:
        return construct_key(value)
    except M0PrimitiveError as exc:
        raise _struct(str(exc)) from exc


def _disposition(value: Any, label: str) -> int:
    disposition = _uint(value, 8, label)
    if disposition not in _DISPOSITIONS:
        raise _struct(label + " is not a permitted disposition")
    return disposition


def _candidate_blockers(value: Any, label: str) -> list[list[Any]]:
    rows: list[list[Any]] = []
    construct_keys: set[bytes] = set()
    for item in _array(value, label):
        row = _array(item, "candidate_blocker")
        if len(row) != 2:
            raise _struct("candidate blocker has the wrong width")
        construct = _construct(row[0])
        construct_key = _encoded(construct)
        if construct_key in construct_keys:
            raise _struct(label + " repeats one semantic construct key")
        construct_keys.add(construct_key)
        rows.append([construct, _text(row[1], "failure_code")])
    return _distinct_sorted(rows, label)


def _require_disposition_blockers(disposition: int, blockers: list[list[Any]], label: str) -> None:
    if disposition in (REPRESENTED, NONINSTANTIATED_OR_DISCARDED) and blockers:
        raise _struct(label + " with no unsupported disposition has blockers")
    if disposition == UNSUPPORTED and not blockers:
        raise _struct(label + " unsupported disposition has no blocker")


def _target_registry(value: Any) -> list[Any]:
    row = _array(value, "provisional_target_registry")
    if len(row) != 3:
        raise _struct("provisional target registry has the wrong width")
    status = _uint(row[0], 8, "registry_status")
    if status != REGISTRY_STATUS_PROVISIONAL_DIAGNOSTIC_ONLY:
        raise _struct("registry status is not provisional diagnostic-only")
    descriptors: list[list[Any]] = []
    raw_descriptors = _array(row[1], "target_descriptors")
    if len(raw_descriptors) != 116:
        raise _struct("provisional target registry must contain exactly 116 descriptors")
    for expected_index, item in enumerate(raw_descriptors):
        descriptor = _array(item, "target_descriptor")
        if len(descriptor) != 3:
            raise _struct("target descriptor has the wrong width")
        index = _uint(descriptor[0], 32, "target index")
        if index != expected_index:
            raise _struct("target descriptors are not indexed densely in ascending order")
        name = _text(descriptor[1], "target name")
        raw_type = _text(descriptor[2], "target raw_qual_type")
        try:
            qtid_ascii_v1(raw_type)
        except Exception as exc:
            raise _struct("target raw_qual_type cannot produce Binding-3 identity") from exc
        descriptors.append([index, name, raw_type])
    descriptor_hash = sha256_digest(canonical_cbor_encode(descriptors))
    if descriptor_hash != FROZEN_TARGET_DESCRIPTORS_CBOR_SHA256:
        raise _struct("target descriptors do not match the frozen Binding-3 projection")
    expected_root = sha256_digest(
        canonical_cbor_encode(
            [
                DIAGNOSTIC_TARGET_REGISTRY_DOMAIN,
                PROTOCOL_ID,
                WIRE_VERSION,
                REGISTRY_STATUS_PROVISIONAL_DIAGNOSTIC_ONLY,
                116,
                descriptors,
            ]
        )
    )
    supplied_root = _bstr32(row[2], "registry_root")
    if supplied_root != expected_root:
        raise _struct("provisional target registry root does not match its exact preimage")
    return [status, descriptors, supplied_root]


def _target_indices(value: Any, registry_size: int, label: str) -> list[int]:
    result = [_uint(item, 32, label + " target index") for item in _array(value, label)]
    if result != sorted(set(result)):
        raise _struct(label + " target indices are not strictly increasing")
    if any([index >= registry_size for index in result]):
        raise _struct(label + " target index is outside the provisional registry")
    return result


def _template_exclusion_proof(
    value: Any,
    *,
    flags: list[int],
    descriptors: Sequence[Sequence[Any]],
    allow_unproven: bool = False,
) -> list[Any]:
    proof = _array(value, "template_exclusion_proof")
    if len(proof) != 5:
        raise _struct("template_exclusion_proof has the wrong width")
    body_dependent = _bit(proof[0], "body_remains_dependent")
    not_concrete = _bit(proof[1], "no_concrete_definition_for_pattern")
    emitted_targets = _target_indices(
        proof[2], len(descriptors), "pattern_emitted_target_indices"
    )
    specialization = _array(proof[3], "specialization_inventory")
    if len(specialization) != 2:
        raise _struct("specialization inventory has the wrong width")
    specialization_complete = _bit(
        specialization[0], "specialization_inventory_complete"
    )
    specialization_subjects = [
        _subject(SOURCE_DEFINITION_INVENTORY, item, descriptors)
        for item in _array(specialization[1], "specialization_subject_keys")
    ]
    specialization_keys = [_encoded(item) for item in specialization_subjects]
    if specialization_keys != sorted(set(specialization_keys)):
        raise _struct("specialization subject keys are not strictly canonical")
    runtime_loci: list[list[Any]] = []
    for item in _array(proof[4], "runtime_root_reference_loci"):
        locus = _array(item, "runtime_root_reference_locus")
        if len(locus) != 3:
            raise _struct("runtime-root reference locus has the wrong width")
        domain = _uint(locus[0], 8, "runtime-root reference domain")
        if domain not in (2, 3):
            raise _struct("runtime-root reference domain is invalid")
        runtime_loci.append(
            [
                domain,
                _subject(_domain_code(domain), locus[1], descriptors),
                _construct(locus[2]),
            ]
        )
    locus_keys = [_encoded(item) for item in runtime_loci]
    if locus_keys != sorted(set(locus_keys)):
        raise _struct("runtime-root reference loci are not strictly canonical")
    canonical = [
        body_dependent,
        not_concrete,
        emitted_targets,
        [specialization_complete, specialization_subjects],
        runtime_loci,
    ]
    if not allow_unproven and (flags[3] != 1 or flags[4] != 0):
        raise _template("discarded row is not a dependent template pattern")
    if not allow_unproven and (
        body_dependent != 1
        or not_concrete != 1
        or emitted_targets
        or specialization_complete != 1
        or runtime_loci
    ):
        raise _template("template-emission exclusion proof is not established")
    return canonical


def _properties(
    value: Any,
    disposition: int,
    descriptors: Sequence[Sequence[Any]],
    allow_template_unproven: bool = False,
) -> list[Any]:
    row = _array(value, "source-definition properties")
    if len(row) != 6:
        raise _struct("source-definition properties have the wrong width")
    flags = [_bit(item, "source-definition property") for item in row[:5]]
    proof = _array(row[5], "template_exclusion_proof")
    if disposition == NONINSTANTIATED_OR_DISCARDED:
        return flags + [
            _template_exclusion_proof(
                proof,
                flags=flags,
                descriptors=descriptors,
                allow_unproven=allow_template_unproven,
            )
        ]
    if proof:
        raise _struct("template-exclusion proof has the wrong disposition")
    return flags + [[]]


def _source_rows(
    value: Any,
    descriptors: Sequence[Sequence[Any]],
    allow_template_unproven: bool = False,
) -> tuple[list[list[Any]], dict[bytes, list[Any]]]:
    rows: list[list[Any]] = []
    by_key: dict[bytes, list[Any]] = {}
    anchor_paths: set[bytes] = set()
    for item in _array(value, "source_definition_rows"):
        row = _array(item, "source_definition_row")
        if len(row) != 4:
            raise _struct("source-definition row has the wrong width")
        subject = _subject(SOURCE_DEFINITION_INVENTORY, row[0], descriptors)
        disposition = _disposition(row[2], "source-definition disposition")
        blockers = _candidate_blockers(row[3], "source-definition candidate_blockers")
        _require_disposition_blockers(disposition, blockers, "source-definition")
        properties = _properties(
            row[1],
            disposition,
            descriptors,
            allow_template_unproven=allow_template_unproven,
        )
        canonical = [subject, properties, disposition, blockers]
        key = _encoded(subject)
        if key in by_key:
            raise _struct("source-definition subject key is duplicated")
        anchor_path = _encoded(subject[0])
        if anchor_path in anchor_paths:
            raise _struct("source definitions collide on one structural AST path")
        anchor_paths.add(anchor_path)
        by_key[key] = canonical
        rows.append(canonical)
    rows = _distinct_sorted(rows, "source_definition_rows")
    canonical_subject_index = {_encoded(row[0]): row for row in rows}
    for canonical_row in rows:
        if canonical_row[2] == NONINSTANTIATED_OR_DISCARDED:
            proof = canonical_row[1][5]
            for specialization_subject in proof[3][1]:
                specialized = canonical_subject_index.get(_encoded(specialization_subject))
                if specialized is None:
                    raise _struct("template proof references an unknown specialization")
                if specialized[1][4] != 1 or specialized[2] not in (REPRESENTED, UNSUPPORTED):
                    raise _struct("template proof references an invalid specialization row")
    return rows, canonical_subject_index


def _phase(value: Any, label: str) -> list[Any]:
    row = _array(value, label)
    if len(row) != 3:
        raise _struct(label + " has the wrong width")
    required = _bit(row[0], label + " phase_required")
    disposition = _disposition(row[1], label + " disposition")
    if disposition == NONINSTANTIATED_OR_DISCARDED:
        raise _struct("template-pattern exclusion is not legal in TU-runtime rows")
    blockers = _candidate_blockers(row[2], label + " candidate_blockers")
    _require_disposition_blockers(disposition, blockers, label)
    if required == 0 and (disposition != REPRESENTED or blockers):
        raise _struct("non-required runtime phase is not exactly NO_RUNTIME_PHASE")
    return [required, disposition, blockers]


def _runtime_rows(
    value: Any, descriptors: Sequence[Sequence[Any]]
) -> tuple[list[list[Any]], int, int, int, int]:
    rows: list[list[Any]] = []
    seen: set[bytes] = set()
    anchor_paths: set[bytes] = set()
    counts = [0, 0, 0, 0]
    for item in _array(value, "tu_runtime_rows"):
        row = _array(item, "tu_runtime_row")
        if len(row) != 4:
            raise _struct("TU-runtime row has the wrong width")
        global_key = _subject(TU_RUNTIME_INVENTORY, row[0], descriptors)
        key = _encoded(global_key)
        if key in seen:
            raise _struct("TU-runtime global key is duplicated")
        seen.add(key)
        anchor_path = _encoded(global_key[8])
        if anchor_path in anchor_paths:
            raise _struct("TU-runtime globals collide on one structural AST path")
        anchor_paths.add(anchor_path)
        runtime_class = _uint(row[1], 8, "runtime_class")
        if runtime_class not in _RUNTIME_CLASSES:
            raise _struct("runtime_class is reserved")
        initialization = _phase(row[2], "initialization_phase")
        destruction = _phase(row[3], "destruction_phase")
        expected_required = {
            1: (0, 0),
            2: (1, 0),
            3: (0, 1),
            4: (1, 1),
        }.get(runtime_class)
        if expected_required is not None and (
            initialization[0], destruction[0]
        ) != expected_required:
            raise _struct("runtime class and phase-required flags disagree")
        unsupported = runtime_class == 5 or any([
            phase[0] == 1 and phase[1] == UNSUPPORTED
            for phase in (initialization, destruction)
        ])
        if runtime_class == 5 and not any([
            phase[0] == 1 and phase[1] == UNSUPPORTED and phase[2]
            for phase in (initialization, destruction)
        ]):
            raise _struct("unsupported runtime class has no required unsupported phase")
        canonical = [global_key, runtime_class, initialization, destruction]
        rows.append(canonical)
        counts[0] += 1
        counts[UNSUPPORTED if unsupported else REPRESENTED] += 1
    rows = _distinct_sorted(rows, "tu_runtime_rows")
    return rows, counts[0], counts[1], counts[2], counts[3]


def _invocation_rows(
    value: Any,
    descriptors: Sequence[Sequence[Any]],
    represented_sources: dict[bytes, list[Any]],
) -> tuple[list[list[Any]], int, int, int, int]:
    rows: list[list[Any]] = []
    seen_instances: set[bytes] = set()
    seen_source_subjects: set[bytes] = set()
    counts = [0, 0, 0, 0]
    for item in _array(value, "invocation_rows"):
        row = _array(item, "invocation_row")
        if len(row) != 2:
            raise _struct("invocation row has the wrong width")
        instance_key = _subject(
            DEFINITION_INVOCATION_INVENTORY, row[0], descriptors
        )
        source_subject = instance_key[1]
        definition = instance_key[2]
        source_key = _encoded(source_subject)
        instance_bytes = _encoded(instance_key)
        if source_key in seen_source_subjects:
            raise _struct("invocation source subject key is duplicated")
        if instance_bytes in seen_instances:
            raise _struct("definition instance key is duplicated")
        seen_source_subjects.add(source_key)
        seen_instances.add(instance_bytes)
        source_row = represented_sources.get(source_key)
        if source_row is None or source_row[2] != REPRESENTED:
            raise _struct("invocation definition is not a represented source definition")
        source_anchor = source_subject[2]
        if (
            source_subject[1] != definition[0]
            or source_anchor[0] != definition[5]
            or source_anchor[1] != definition[6]
            or source_anchor[2] != definition[7]
        ):
            raise _struct("definition instance fields are not byte-identical")
        occurrence_rows: list[list[Any]] = []
        occurrence_keys: set[bytes] = set()
        for occurrence in _array(row[1], "occurrence_rows"):
            occurrence_row = _array(occurrence, "occurrence_row")
            if len(occurrence_row) != 3:
                raise _struct("occurrence row has the wrong width")
            construct = _construct(occurrence_row[0])
            construct_key = _encoded(construct)
            if construct_key in occurrence_keys:
                raise _struct("occurrence construct key is duplicated")
            occurrence_keys.add(construct_key)
            disposition = _disposition(occurrence_row[1], "occurrence disposition")
            if disposition == NONINSTANTIATED_OR_DISCARDED:
                raise _struct("template-pattern exclusion is not legal in invocation rows")
            blockers = _candidate_blockers(
                occurrence_row[2], "occurrence candidate_blockers"
            )
            _require_disposition_blockers(disposition, blockers, "occurrence")
            occurrence_rows.append([construct, disposition, blockers])
            counts[0] += 1
            counts[disposition] += 1
        occurrence_rows = _distinct_sorted(occurrence_rows, "occurrence_rows")
        rows.append([instance_key, occurrence_rows])
    instance_keys = [_encoded(row[0]) for row in rows]
    if len(instance_keys) != len(set(instance_keys)):
        raise _struct("invocation definition instances are duplicated")
    rows = [
        row
        for _, row in sorted(
            zip(instance_keys, rows, strict=True), key=lambda item: item[0]
        )
    ]
    return rows, counts[0], counts[1], counts[2], counts[3]


def _counts(value: Any, label: str) -> list[int]:
    row = _array(value, label)
    if len(row) != 4:
        raise _struct(label + " has the wrong width")
    return [_uint(item, 64, label + " count") for item in row]


def _summary(value: Any) -> list[Any]:
    row = _array(value, "census_summary")
    if len(row) != 4:
        raise _struct("census_summary has the wrong width")
    return [_counts(row[index], label) for index, label in enumerate((
        "source_definition_counts",
        "tu_runtime_counts",
        "invocation_counts",
    ))] + [_uint(row[3], 64, "total_blockers")]


def _ordering_key(value: Any, descriptors: Sequence[Sequence[Any]]) -> list[Any]:
    row = _array(value, "ordered_blocker")
    if len(row) != 4:
        raise _struct("ordered blocker has the wrong width")
    domain = _uint(row[0], 8, "ordered blocker domain_code")
    if domain not in (1, 2, 3):
        raise _struct("ordered blocker domain_code is invalid")
    subject = _subject(_domain_code(domain), row[1], descriptors)
    construct = _construct(row[2])
    failure = _text(row[3], "ordered blocker failure_code")
    return [domain, subject, construct, failure]


def _reconstruct_blockers(
    source_rows: list[list[Any]],
    runtime_rows: list[list[Any]],
    invocation_rows: list[list[Any]],
) -> list[list[Any]]:
    result: list[list[Any]] = []
    for subject, _properties_row, disposition, blockers in source_rows:
        if disposition == UNSUPPORTED:
            result.extend([[1, subject, blocker[0], blocker[1]] for blocker in blockers])
    for global_key, _runtime_class, initialization, destruction in runtime_rows:
        for phase in (initialization, destruction):
            if phase[1] == UNSUPPORTED:
                result.extend([[2, global_key, blocker[0], blocker[1]] for blocker in phase[2]])
    for definition_instance, occurrences in invocation_rows:
        for construct, disposition, blockers in occurrences:
            if disposition == UNSUPPORTED:
                result.extend(
                    [[3, definition_instance, blocker[0], blocker[1]] for blocker in blockers]
                )
    return result


def _verify_census_construct_uniqueness(
    source_rows: Sequence[Sequence[Any]],
    runtime_rows: Sequence[Sequence[Any]],
    invocation_rows: Sequence[Sequence[Any]],
) -> None:
    seen: dict[bytes, str] = {}

    def add(construct: Any, owner: str) -> bytes:
        key = _encoded(construct)
        previous = seen.get(key)
        if previous is not None:
            raise _struct(
                "semantic construct key is claimed by both " + previous + " and " + owner
            )
        seen[key] = owner
        return key

    for row in source_rows:
        for blocker in row[3]:
            add(blocker[0], "source-definition blockers")
    for row in runtime_rows:
        for phase in row[2:4]:
            for blocker in phase[2]:
                add(blocker[0], "TU-runtime blockers")
    for _definition_instance, occurrences in invocation_rows:
        for occurrence in occurrences:
            occurrence_key = add(occurrence[0], "invocation occurrences")
            for blocker in occurrence[2]:
                blocker_key = _encoded(blocker[0])
                # An unsupported occurrence's blocker names that exact candidate.
                # It is a reference, not a second semantic construct record.
                if blocker_key != occurrence_key:
                    add(blocker[0], "invocation blockers")


def _verify_blockers(
    supplied: Any,
    reconstructed: list[list[Any]],
    descriptors: Sequence[Sequence[Any]],
) -> list[list[Any]]:
    supplied_rows = [
        _ordering_key(item, descriptors)
        for item in _array(supplied, "ordered_blockers")
    ]
    reconstructed_keys = [_encoded(item) for item in reconstructed]
    if len(reconstructed_keys) != len(set(reconstructed_keys)):
        raise _struct("candidate blocker identity is duplicated")
    supplied_keys = [_encoded(item) for item in supplied_rows]
    if len(supplied_keys) != len(set(supplied_keys)):
        raise _struct("ordered blocker is duplicated")
    if set(supplied_keys) != set(reconstructed_keys):
        raise _struct("ordered blockers do not exactly reconstruct candidate blockers")
    return [row for _, row in sorted([(_encoded(row), row) for row in reconstructed], key=lambda item: item[0])]


def _validate(
    value: Any,
    *,
    bound_profile_cbor: bytes | None = None,
    allow_template_unproven: bool = False,
) -> list[Any]:
    value = _wire(value)
    top = _array(value, "DIAGNOSTIC_CENSUS_V1")
    if len(top) != 9:
        raise _struct("DIAGNOSTIC_CENSUS_V1 has the wrong width")
    if top[0] != PROTOCOL_ID or type(top[0]) is not int:
        raise _struct("protocol identifier is invalid")
    if top[1] != WIRE_VERSION or type(top[1]) is not int:
        raise _struct("wire version is invalid")

    collector_profile = _collector_profile(top[2], bound_profile_cbor)

    registry = _target_registry(top[3])
    descriptors = registry[1]
    summary = _summary(top[4])
    source_rows, source_index = _source_rows(
        top[5],
        descriptors,
        allow_template_unproven=allow_template_unproven,
    )
    represented_sources = {
        key: row
        for key, row in source_index.items()
        if row[2] == REPRESENTED
    }
    runtime_rows, runtime_total, runtime_represented, runtime_discarded, runtime_unsupported = _runtime_rows(
        top[6], descriptors
    )
    invocation_rows, invocation_total, invocation_represented, invocation_discarded, invocation_unsupported = (
        _invocation_rows(top[7], descriptors, represented_sources)
    )
    if len(represented_sources) != len(invocation_rows):
        raise _struct("represented source definitions and invocation rows differ")
    invocation_keys = {_encoded(row[0][1]) for row in invocation_rows}
    if invocation_keys != set(represented_sources):
        raise _struct("invocation definition coverage is incomplete")

    actual_counts = [
        [
            len(source_rows),
            sum([row[2] == REPRESENTED for row in source_rows]),
            sum([row[2] == NONINSTANTIATED_OR_DISCARDED for row in source_rows]),
            sum([row[2] == UNSUPPORTED for row in source_rows]),
        ],
        [runtime_total, runtime_represented, runtime_discarded, runtime_unsupported],
        [invocation_total, invocation_represented, invocation_discarded, invocation_unsupported],
    ]
    reconstructed = _reconstruct_blockers(source_rows, runtime_rows, invocation_rows)
    _verify_census_construct_uniqueness(source_rows, runtime_rows, invocation_rows)
    ordered_blockers = _verify_blockers(top[8], reconstructed, descriptors)
    actual_summary = actual_counts + [len(ordered_blockers)]
    if summary != actual_summary:
        raise _struct("census summary counts do not match the complete rows")
    return [
        PROTOCOL_ID,
        WIRE_VERSION,
        collector_profile,
        registry,
        actual_summary,
        source_rows,
        runtime_rows,
        invocation_rows,
        ordered_blockers,
    ]


def validate_diagnostic_census(
    value: Any, *, bound_profile_cbor: bytes | None = None
) -> list[Any]:
    """Validate an already-final, semantically canonical census artifact."""

    try:
        wire = _wire(value)
        canonical = _validate(wire, bound_profile_cbor=bound_profile_cbor)
        if wire != canonical:
            raise _struct("final diagnostic census is not canonically ordered")
        return canonical
    except M0DiagnosticCensusError:
        raise
    except Exception as exc:  # malformed foreign objects must fail closed
        raise _struct("malformed diagnostic census") from exc


def canonicalize_diagnostic_census(
    value: Any, *, bound_profile_cbor: bytes | None = None
) -> list[Any]:
    """Canonicalize a collector result after exact structural verification."""

    try:
        return _validate(value, bound_profile_cbor=bound_profile_cbor)
    except M0DiagnosticCensusError:
        raise
    except Exception as exc:
        raise _struct("malformed diagnostic census") from exc


def encode_diagnostic_census(
    value: Any, *, bound_profile_cbor: bytes | None = None
) -> bytes:
    """Return canonical CBOR for a validated arrays-only census."""

    try:
        return canonical_cbor_encode(
            canonicalize_diagnostic_census(
                value, bound_profile_cbor=bound_profile_cbor
            )
        )
    except M0PrimitiveError as exc:
        raise _struct("diagnostic census cannot be encoded") from exc


def decode_diagnostic_census(
    raw: bytes, *, bound_profile_cbor: bytes | None = None
) -> list[Any]:
    """Decode and validate one canonical CBOR diagnostic census."""

    try:
        decoded = canonical_cbor_decode(raw)
    except (M0PrimitiveError, TypeError) as exc:
        raise _struct("diagnostic census CBOR is invalid") from exc
    validated = validate_diagnostic_census(
        decoded, bound_profile_cbor=bound_profile_cbor
    )
    if canonical_cbor_encode(validated) != raw:
        raise _struct("diagnostic census CBOR is not byte-canonical")
    return validated


def _raw_transport_blockers(
    source_rows: Sequence[Any],
    runtime_rows: Sequence[Any],
    invocation_rows: Sequence[Any],
) -> list[list[Any]]:
    blockers: list[list[Any]] = []
    for item in source_rows:
        row = _array(item, "raw source_definition_row")
        if len(row) != 4:
            raise _struct("raw source-definition row has the wrong width")
        for blocker_value in _array(row[3], "raw source candidate_blockers"):
            blocker = _array(blocker_value, "raw source candidate_blocker")
            if len(blocker) != 2:
                raise _struct("raw source candidate blocker has the wrong width")
            blockers.append([1, row[0], blocker[0], blocker[1]])
    for item in runtime_rows:
        row = _array(item, "raw tu_runtime_row")
        if len(row) != 4:
            raise _struct("raw TU-runtime row has the wrong width")
        for phase_value in row[2:4]:
            phase = _array(phase_value, "raw runtime phase")
            if len(phase) != 3:
                raise _struct("raw runtime phase has the wrong width")
            for blocker_value in _array(phase[2], "raw runtime candidate_blockers"):
                blocker = _array(blocker_value, "raw runtime candidate_blocker")
                if len(blocker) != 2:
                    raise _struct("raw runtime candidate blocker has the wrong width")
                blockers.append([2, row[0], blocker[0], blocker[1]])
    for item in invocation_rows:
        row = _array(item, "raw invocation_row")
        if len(row) != 2:
            raise _struct("raw invocation row has the wrong width")
        definition_instance = _array(row[0], "raw definition instance key")
        try:
            definition_instance_key_v2(definition_instance)
        except M0PrimitiveError as exc:
            raise _struct(str(exc)) from exc
        for occurrence_value in _array(row[1], "raw occurrence_rows"):
            occurrence = _array(occurrence_value, "raw occurrence_row")
            if len(occurrence) != 3:
                raise _struct("raw occurrence row has the wrong width")
            for blocker_value in _array(
                occurrence[2], "raw occurrence candidate_blockers"
            ):
                blocker = _array(blocker_value, "raw occurrence candidate_blocker")
                if len(blocker) != 2:
                    raise _struct("raw occurrence candidate blocker has the wrong width")
                blockers.append([3, definition_instance, blocker[0], blocker[1]])
    return blockers


def canonicalize_native_diagnostic_transport(
    raw: bytes,
    *,
    collector_profile: Any,
    bound_profile_cbor: bytes | None = None,
    allow_template_unproven: bool = False,
) -> list[Any]:
    """Convert one complete internal native transport into the normative wire.

    The complete profile is supplied by the surrounding pinned native runner.
    This zero-authority function validates and preserves it but cannot prove
    which executable produced ``raw``.
    """

    try:
        decoded = canonical_cbor_decode(raw)
        transport = _wire(decoded)
        top = _array(transport, "native diagnostic transport")
        if len(top) != 5:
            raise _struct("native diagnostic transport has the wrong width")
        descriptors = _array(top[0], "raw target_descriptors")
        counts = _array(top[1], "raw census counts")
        if len(counts) != 3:
            raise _struct("raw census counts have the wrong width")
        source_rows = _array(top[2], "raw source_definition_rows")
        runtime_rows = _array(top[3], "raw tu_runtime_rows")
        invocation_rows = _array(top[4], "raw invocation_rows")
        ordered_blockers = _raw_transport_blockers(
            source_rows, runtime_rows, invocation_rows
        )
        normalized_profile = _collector_profile(
            _wire(collector_profile), bound_profile_cbor
        )
        exact_profile_cbor = (
            canonical_cbor_encode(normalized_profile)
            if bound_profile_cbor is None
            else bound_profile_cbor
        )
        registry_root = sha256_digest(
            canonical_cbor_encode(
                [
                    DIAGNOSTIC_TARGET_REGISTRY_DOMAIN,
                    PROTOCOL_ID,
                    WIRE_VERSION,
                    REGISTRY_STATUS_PROVISIONAL_DIAGNOSTIC_ONLY,
                    116,
                    descriptors,
                ]
            )
        )
        candidate = [
            PROTOCOL_ID,
            WIRE_VERSION,
            normalized_profile,
            [REGISTRY_STATUS_PROVISIONAL_DIAGNOSTIC_ONLY, descriptors, registry_root],
            [counts[0], counts[1], counts[2], len(ordered_blockers)],
            source_rows,
            runtime_rows,
            invocation_rows,
            ordered_blockers,
        ]
        return _validate(
            candidate,
            bound_profile_cbor=exact_profile_cbor,
            allow_template_unproven=allow_template_unproven,
        )
    except M0DiagnosticCensusError:
        raise
    except (M0PrimitiveError, TypeError, ValueError) as exc:
        raise _struct("native diagnostic transport is malformed") from exc


def canonicalize_diagnostic_census_v1(raw_collector_bytes):
    """Return the exact Amendment-3 entry-result ABI for one raw census."""

    try:
        if type(raw_collector_bytes) is not bytes:
            raise _struct("raw collector input is not immutable bytes")
        bound_profile_cbor = V631302_BOUND_COLLECTOR_PROFILE_CBOR
        if type(bound_profile_cbor) is not bytes:
            raise _struct("reserved collector-profile binding is invalid")
        profile = canonical_cbor_decode(bound_profile_cbor)
        _collector_profile(profile, bound_profile_cbor)
        try:
            census = canonicalize_native_diagnostic_transport(
                raw_collector_bytes,
                collector_profile=profile,
                bound_profile_cbor=bound_profile_cbor,
            )
        except M0DiagnosticCensusError as exc:
            if type(exc) is not _M0TemplateEmissionError:
                raise
            canonicalize_native_diagnostic_transport(
                raw_collector_bytes,
                collector_profile=profile,
                bound_profile_cbor=bound_profile_cbor,
                allow_template_unproven=True,
            )
            return canonical_cbor_encode([PROTOCOL_ID, WIRE_VERSION, 2, b""])
        payload = canonical_cbor_encode(census)
        if canonical_cbor_encode(census[2]) != bound_profile_cbor:
            raise _struct("successful census profile differs from the bound bytes")
        return canonical_cbor_encode([PROTOCOL_ID, WIRE_VERSION, 0, payload])
    except Exception:
        return canonical_cbor_encode([PROTOCOL_ID, WIRE_VERSION, 1, b""])


validate_and_canonicalize = canonicalize_diagnostic_census
canonicalize_census = canonicalize_diagnostic_census
