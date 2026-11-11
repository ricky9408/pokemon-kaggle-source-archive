"""G2 candidate-population content conformance for Evaluation v6.3.1.

G2 knows only neutral U01-U16 candidate identifiers, canonical payload bytes,
and candidate-policy signatures. It does not authenticate semantic assertions,
project components, assign campaign roles, or create any authority.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
import hashlib
import io
from itertools import combinations
import json
from threading import RLock
import unicodedata
import weakref
import zlib
from typing import Any

from .common import (
    canonical_base64,
    canonical_integer,
    canonical_json_bytes,
    canonical_string_list,
    exact,
    fail,
    freeze,
    identifier,
    sha256,
    verify_signature_set,
    zero_authority,
)
from .policy import ValidatedV631Policy, require_validated_policy


POPULATION_SCHEMA = "eval.v6.3.1.g2-candidate-population"
ARTIFACT_SCHEMA = "eval.v6.3.1.content-addressed-artifact"
UNIT_SCHEMA = "eval.v6.3.1.g2-candidate-unit"
ARCHIVE_EVIDENCE_SCHEMA = "eval.v6.3.1.archive-evidence"
ARCHIVE_ENTRY_MANIFEST_SCHEMA = "eval.v6.3.1.archive-entry-manifest"
PACKAGE_EVIDENCE_SCHEMA = "eval.v6.3.1.package-evidence"
SOURCE_EVIDENCE_SCHEMA = "eval.v6.3.1.source-evidence"
SOURCE_TREE_SCHEMA = "eval.v6.3.1.source-tree"
SOURCE_HISTORY_SCHEMA = "eval.v6.3.1.source-history"
BUILD_RECIPE_SCHEMA = "eval.v6.3.1.build-recipe"
TOOLCHAIN_LOCK_SCHEMA = "eval.v6.3.1.toolchain-lock"
CONTAINER_PROFILE_SCHEMA = "eval.v6.3.1.container-profile"
ENGINE_PROFILE_SCHEMA = "eval.v6.3.1.engine-profile"
RULESET_PROFILE_SCHEMA = "eval.v6.3.1.ruleset-profile"
BUILD_EVIDENCE_SCHEMA = "eval.v6.3.1.build-evidence"
REBUILD_RECEIPT_SCHEMA = "eval.v6.3.1.linux-amd64-rebuild-receipt"
SAFETY_AUDIT_SCHEMA = "eval.v6.3.1.structured-safety-audit"
SEMANTIC_DISCLOSURE_SCHEMA = "eval.v6.3.1.candidate-semantic-disclosure"
CONTROL_EVIDENCE_SCHEMA = "eval.v6.3.1.candidate-control-evidence"
ANCESTRY_EVIDENCE_SCHEMA = "eval.v6.3.1.candidate-ancestry-evidence"
FORKS_EVIDENCE_SCHEMA = "eval.v6.3.1.candidate-forks-evidence"
THIRD_PARTY_INPUTS_SCHEMA = "eval.v6.3.1.candidate-third-party-inputs"
INTERVENTION_EVIDENCE_SCHEMA = "eval.v6.3.1.candidate-intervention-evidence"
ESCROW_RECEIPT_SCHEMA = "eval.v6.3.1.candidate-escrow-receipt"
CONTRIBUTOR_CHALLENGE_PRECOMMIT_SCHEMA = "eval.v6.3.1.contributor-challenge-precommit"
PAIR_CLASSIFICATION_SCHEMA = "eval.v6.3.1.candidate-pair-classification"
AUDITOR_CLASSIFICATION_SCHEMA = "eval.v6.3.1.candidate-auditor-classification"
PAIR_REVIEW_EVIDENCE_SCHEMA = "eval.v6.3.1.candidate-pair-review-evidence"
PAIR_ANALYSIS_SCHEMA = "eval.v6.3.1.candidate-pair-analysis"
PAIR_ANALYSIS_EVIDENCE_SCHEMA = "eval.v6.3.1.candidate-pair-analysis-evidence"
VALIDATED_POPULATION_SCHEMA = "eval.v6.3.1.g2-schema-conformant-candidate-population"
VERDICT_SCHEMA = "eval.v6.3.1.g2-candidate-population-verdict"

DOMAIN_SOURCE_EVIDENCE = b"EVAL-V631/G2-SOURCE-EVIDENCE\0"
DOMAIN_BUILD_EVIDENCE = b"EVAL-V631/G2-BUILD-EVIDENCE\0"
DOMAIN_SEMANTIC_DISCLOSURE = b"EVAL-V631/G2-SEMANTIC-DISCLOSURE\0"
DOMAIN_PAIR_CLASSIFICATION = b"EVAL-V631/G2-PAIR-CLASSIFICATION\0"
DOMAIN_REBUILD_RECEIPT = b"EVAL-V631/G2-LINUX-AMD64-REBUILD-RECEIPT\0"

CANDIDATE_IDS = tuple(f"U{index:02d}" for index in range(1, 17))
SOURCE_MODES = ("PUBLIC_SOURCE", "PRIVATE_DUAL_AUDITOR_ESCROW")
SOURCE_LINEAGE_STATES = ("INDEPENDENT", "SHARED", "DERIVED", "UNKNOWN", "CONFLICT")
INTERVENTION_STATES = ("DISTINCT", "OVERLAP", "SAME", "UNKNOWN", "CONFLICT")
REQUIRED_SAFETY_CHECK_IDS = (
    "archive_manifest_closed",
    "forbidden_archive_entries_absent",
    "runtime_safety_audit",
)

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_UNCOMPRESSED_TAR_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 256
MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_PATH_BYTES = 255

_ARTIFACT_FIELDS = frozenset({"schema", "content_sha256", "payload_base64"})
_ARCHIVE_FIELDS = frozenset({"schema", "archive_filename", "archive_byte_length", "archive_sha256", "archive_entry_manifest_sha256", "evidence_root_sha256"})
_PACKAGE_FIELDS = frozenset({"schema", "archive_sha256", "archive_byte_length", "archive_entry_manifest_sha256", "source_tree_sha256", "build_recipe_sha256", "package_root_sha256"})
_SOURCE_FIELDS = frozenset({"schema", "policy_sha256", "source_mode", "source_tree_sha256", "source_history_root_sha256", "auditor_a_plaintext_root_sha256", "auditor_b_plaintext_root_sha256", "evidence_root_sha256", "signatures"})
_BUILD_FIELDS = frozenset({"schema", "policy_sha256", "package_root_sha256", "source_evidence_root_sha256", "build_recipe_sha256", "toolchain_lock_sha256", "container_image_sha256", "engine_sha256", "ruleset_sha256", "rebuild_receipts", "evidence_root_sha256", "signatures"})
_REBUILD_RECEIPT_FIELDS = frozenset({"schema", "policy_sha256", "auditor_id", "operating_system", "architecture", "rebuild_command_argv", "build_recipe_sha256", "source_tree_sha256", "toolchain_lock_sha256", "container_image_sha256", "engine_sha256", "ruleset_sha256", "output_archive_sha256", "output_archive_byte_length", "output_archive_entry_manifest_sha256", "safety_audit_root_sha256", "signature"})
_SEMANTIC_DISCLOSURE_FIELDS = frozenset({"schema", "policy_sha256", "declared_principal_ids", "control_evidence_root_sha256", "ancestry_root_sha256", "forks_root_sha256", "third_party_inputs_root_sha256", "intervention_evidence_root_sha256", "escrow_receipt_root_sha256", "contributor_challenge_precommit_sha256", "evidence_root_sha256", "signatures"})
_UNIT_FIELDS = frozenset({"schema", "candidate_id", "archive", "package", "source", "build", "semantic_disclosure", "evidence_root_sha256"})
_AUDITOR_CLASSIFICATION_FIELDS = frozenset({"schema", "auditor_id", "source_state", "lineage_control_state", "development_control_state", "intervention_state", "source_review_root_sha256", "lineage_control_review_root_sha256", "development_control_review_root_sha256", "intervention_review_root_sha256", "analysis_evidence_root_sha256", "analysis_root_sha256"})
_PAIR_FIELDS = frozenset({"schema", "policy_sha256", "left_candidate_id", "right_candidate_id", "classifications", "signatures"})
_POPULATION_FIELDS = frozenset({"schema", "artifacts", "units", "pair_classifications", "pair_classifications_root_sha256", "evidence_root_sha256"})

_VALIDATED_SENTINEL = object()
_ISSUED_POPULATIONS: dict[int, tuple[weakref.ReferenceType[Any], bytes, Mapping[str, Any]]] = {}
_ISSUED_POPULATIONS_LOCK = RLock()


@dataclass(frozen=True)
class ValidatedCandidatePopulation(Mapping[str, Any]):
    """Immutable G2 content-conformance result, never semantic validation."""

    _data: Mapping[str, Any]
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _VALIDATED_SENTINEL:
            raise ValueError("ValidatedCandidatePopulation can only be created by validate_candidate_population")

    def __getitem__(self, key: str) -> Any:
        return _require_issued_population(self)[key]

    def __iter__(self) -> Iterator[str]:
        return iter(_require_issued_population(self))

    def __len__(self) -> int:
        return len(_require_issued_population(self))


def _json_snapshot(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in value:
            if type(key) is not str or key in result:
                raise TypeError("validated population mappings require unique string keys")
            result[key] = _json_snapshot(value[key])
        return result
    if type(value) in {list, tuple}:
        return [_json_snapshot(item) for item in value]
    if value is None or type(value) in {str, int, bool}:
        return value
    raise TypeError(f"validated population contains unsupported value type {type(value).__name__}")


def _register_issued_population(value: ValidatedCandidatePopulation, retained_data: Mapping[str, Any]) -> None:
    canonical_bytes = canonical_json_bytes(_json_snapshot(retained_data))
    identity = id(value)

    def remove(reference: weakref.ReferenceType[Any]) -> None:
        with _ISSUED_POPULATIONS_LOCK:
            current = _ISSUED_POPULATIONS.get(identity)
            if current is not None and current[0] is reference:
                _ISSUED_POPULATIONS.pop(identity, None)

    reference = weakref.ref(value, remove)
    with _ISSUED_POPULATIONS_LOCK:
        _ISSUED_POPULATIONS[identity] = (reference, canonical_bytes, retained_data)


def _require_issued_population(value: Any) -> Mapping[str, Any]:
    if type(value) is not ValidatedCandidatePopulation:
        raise fail("POPULATION_OBJECT_NOT_ISSUED", "an issued immutable G2 candidate population is required")
    with _ISSUED_POPULATIONS_LOCK:
        issued = _ISSUED_POPULATIONS.get(id(value))
    if issued is None or issued[0]() is not value:
        raise fail("POPULATION_OBJECT_NOT_ISSUED", "candidate population object was not issued by this verifier")
    if value._construction_token is not _VALIDATED_SENTINEL:
        raise fail("POPULATION_OBJECT_TAMPERED", "candidate population construction token was modified")
    try:
        current_bytes = canonical_json_bytes(_json_snapshot(value._data))
    except (RuntimeError, TypeError, ValueError, RecursionError) as exc:
        raise fail("POPULATION_OBJECT_TAMPERED", "candidate population data is no longer canonical") from exc
    if current_bytes != issued[1]:
        raise fail("POPULATION_OBJECT_TAMPERED", "candidate population data differs from the verifier-retained bytes")
    return issued[2]


def _required_pairs() -> tuple[tuple[str, str], ...]:
    return tuple(combinations(CANDIDATE_IDS, 2))


def _artifacts(value: Any) -> dict[str, bytes]:
    if type(value) is not list:
        raise fail("ARTIFACT_STORE_INVALID", "artifacts must be a canonical list")
    result: dict[str, bytes] = {}
    previous = ""
    for index, raw in enumerate(value):
        item = exact(raw, _ARTIFACT_FIELDS, f"artifact {index}", code="ARTIFACT_STORE_INVALID")
        if item["schema"] != ARTIFACT_SCHEMA:
            raise fail("ARTIFACT_STORE_INVALID", "artifact schema mismatch")
        digest = sha256(item["content_sha256"], "artifact content sha256", code="ARTIFACT_STORE_INVALID")
        if digest <= previous or digest in result:
            raise fail("ARTIFACT_STORE_INVALID", "artifacts must be unique and canonically sorted")
        payload = canonical_base64(item["payload_base64"], "artifact payload", code="ARTIFACT_STORE_INVALID")
        if hashlib.sha256(payload).hexdigest() != digest:
            raise fail("ARTIFACT_PAYLOAD_HASH_MISMATCH", "artifact payload bytes do not match content sha256")
        result[digest] = payload
        previous = digest
    return result


def _payload(artifacts: Mapping[str, bytes], root: Any, label: str, *, expected: bytes | None = None) -> str:
    digest = sha256(root, label, code="POPULATION_EVIDENCE_INVALID")
    payload = artifacts.get(digest)
    if payload is None:
        raise fail("ARTIFACT_PAYLOAD_MISSING", f"{label} has no content-addressed payload")
    if expected is not None and payload != expected:
        raise fail("ARTIFACT_PAYLOAD_MISMATCH", f"{label} payload is not the required canonical bytes")
    return digest


def _canonical_payload(artifacts: Mapping[str, bytes], root: Any, label: str, value: Mapping[str, Any] | list[Any]) -> str:
    return _payload(artifacts, root, label, expected=canonical_json_bytes(value))


def _canonical_json(payload: bytes, *, label: str, code: str) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            payload,
            object_pairs_hook=reject_duplicate,
            parse_float=lambda _: (_ for _ in ()).throw(ValueError("float")),
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise fail(code, f"{label} is not canonical JSON") from exc
    if canonical_json_bytes(parsed) != payload:
        raise fail(code, f"{label} is not canonical JSON bytes")
    return parsed


def _json_artifact(artifacts: Mapping[str, bytes], root: Any, label: str, *, code: str) -> tuple[str, Any]:
    digest = _payload(artifacts, root, label)
    return digest, _canonical_json(artifacts[digest], label=label, code=code)


def _canonical_path(value: Any, label: str, *, code: str) -> str:
    path = identifier(value, label, code=code)
    encoded = path.encode("utf-8")
    parts = path.split("/")
    if (
        path != unicodedata.normalize("NFC", path)
        or path.startswith("/")
        or path.endswith("/")
        or "\\" in path
        or any(part in {"", ".", "..", "__pycache__"} for part in parts)
        or path.endswith(".pyc")
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
        or len(encoded) > MAX_PATH_BYTES
    ):
        raise fail(code, f"{label} is not an ASCII or NFC UTF-8 canonical relative path")
    return path


def _tar_octal(field: bytes, label: str) -> int:
    stripped = field.rstrip(b"\0 ")
    if not stripped or any(byte not in b"01234567" for byte in stripped):
        raise fail("ARCHIVE_PROFILE_INVALID", f"{label} is not canonical USTAR octal")
    return int(stripped, 8)


def _ustar_text(field: bytes, label: str) -> str:
    if b"\0" in field:
        raw, padding = field.split(b"\0", 1)
        if any(padding):
            raise fail("ARCHIVE_PROFILE_INVALID", f"{label} has noncanonical USTAR padding")
    else:
        raw = field
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise fail("ARCHIVE_PROFILE_INVALID", f"{label} is not UTF-8") from exc


def _decompress_single_gzip(archive_bytes: bytes, *, candidate_id: str) -> bytes:
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise fail("ARCHIVE_RESOURCE_LIMIT", f"{candidate_id} compressed archive exceeds the resource limit")
    inflater = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        payload = inflater.decompress(archive_bytes, MAX_UNCOMPRESSED_TAR_BYTES + 1)
        if inflater.unconsumed_tail or len(payload) > MAX_UNCOMPRESSED_TAR_BYTES:
            raise fail("ARCHIVE_RESOURCE_LIMIT", f"{candidate_id} expanded tar exceeds the resource limit")
        payload += inflater.flush()
    except zlib.error as exc:
        raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} archive is not a valid gzip member") from exc
    if len(payload) > MAX_UNCOMPRESSED_TAR_BYTES:
        raise fail("ARCHIVE_RESOURCE_LIMIT", f"{candidate_id} expanded tar exceeds the resource limit")
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} archive must contain exactly one gzip member with no trailing data")
    return payload


def _parse_ustar(archive_bytes: bytes, *, candidate_id: str) -> list[dict[str, str]]:
    payload = _decompress_single_gzip(archive_bytes, candidate_id=candidate_id)
    if not payload or len(payload) % 512:
        raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} tar is not block-aligned USTAR")
    observed: list[dict[str, str]] = []
    seen: set[str] = set()
    offset = 0
    while offset + 512 <= len(payload):
        header = payload[offset : offset + 512]
        if header == b"\0" * 512:
            if payload[offset + 512 : offset + 1024] != b"\0" * 512 or any(payload[offset + 1024 :]):
                raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} tar has data after its canonical end marker")
            break
        if len(observed) >= MAX_ARCHIVE_ENTRIES:
            raise fail("ARCHIVE_RESOURCE_LIMIT", f"{candidate_id} archive has too many entries")
        expected_checksum = _tar_octal(header[148:156], f"{candidate_id} header checksum")
        checksum_header = header[:148] + b" " * 8 + header[156:]
        if sum(checksum_header) != expected_checksum:
            raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} USTAR header checksum mismatch")
        if header[257:263] != b"ustar\0" or header[263:265] != b"00" or header[156:157] != b"0":
            raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} permits only POSIX USTAR regular-file headers")
        if any(header[157:257]):
            raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} USTAR entries must not contain link targets")
        name = _ustar_text(header[0:100], f"{candidate_id} USTAR name")
        prefix = _ustar_text(header[345:500], f"{candidate_id} USTAR prefix")
        path = _canonical_path(f"{prefix}/{name}" if prefix else name, f"{candidate_id} archive path", code="ARCHIVE_PROFILE_INVALID")
        if path in seen:
            raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} archive contains duplicate paths")
        seen.add(path)
        mode = _tar_octal(header[100:108], f"{candidate_id} {path} mode")
        if mode not in {0o644, 0o755}:
            raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} file mode must be 0644 or 0755")
        size = _tar_octal(header[124:136], f"{candidate_id} {path} size")
        if size > MAX_ENTRY_BYTES:
            raise fail("ARCHIVE_RESOURCE_LIMIT", f"{candidate_id} archive entry exceeds the resource limit")
        data_start = offset + 512
        data_end = data_start + size
        padded_end = data_start + ((size + 511) // 512) * 512
        if padded_end > len(payload) or any(payload[data_end:padded_end]):
            raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} archive entry is truncated or has nonzero padding")
        data = payload[data_start:data_end]
        observed.append({"path": path, "mode": str(mode), "byte_length": str(size), "sha256": hashlib.sha256(data).hexdigest()})
        offset = padded_end
    else:
        raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} tar has no canonical end marker")
    paths = [entry["path"] for entry in observed]
    if not paths or paths != sorted(paths):
        raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} archive paths must be nonempty and canonically sorted")
    for index, path in enumerate(paths):
        if any(other.startswith(path + "/") for other in paths[index + 1 :]):
            raise fail("ARCHIVE_PROFILE_INVALID", f"{candidate_id} archive has a file-prefix collision")
    return observed


def _manifest_entries(value: Any, *, label: str, code: str) -> list[dict[str, str]]:
    if type(value) is not list or not value or len(value) > MAX_ARCHIVE_ENTRIES:
        raise fail(code, f"{label} must contain a bounded nonempty entry list")
    result: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        item = exact(raw, frozenset({"path", "mode", "byte_length", "sha256"}), f"{label} entry {index}", code=code)
        path = _canonical_path(item["path"], f"{label} path", code=code)
        mode = canonical_integer(item["mode"], f"{label} mode", code=code)
        size = canonical_integer(item["byte_length"], f"{label} byte length", code=code)
        if mode not in {0o644, 0o755} or size > MAX_ENTRY_BYTES:
            raise fail(code, f"{label} entry mode or size is outside the canonical profile")
        result.append({"path": path, "mode": item["mode"], "byte_length": item["byte_length"], "sha256": sha256(item["sha256"], f"{label} hash", code=code)})
    paths = [entry["path"] for entry in result]
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise fail(code, f"{label} entries must be unique and canonically sorted")
    for index, path in enumerate(paths):
        if any(other.startswith(path + "/") for other in paths[index + 1 :]):
            raise fail(code, f"{label} contains a file-prefix collision")
    return result


def _archive_manifest(artifacts: Mapping[str, bytes], root: str, archive_bytes: bytes, *, candidate_id: str) -> tuple[str, list[dict[str, str]]]:
    _, parsed = _json_artifact(artifacts, root, f"{candidate_id} archive-entry manifest", code="ARCHIVE_MANIFEST_INVALID")
    item = exact(parsed, frozenset({"schema", "entries"}), f"{candidate_id} archive-entry manifest", code="ARCHIVE_MANIFEST_INVALID")
    if item["schema"] != ARCHIVE_ENTRY_MANIFEST_SCHEMA:
        raise fail("ARCHIVE_MANIFEST_INVALID", f"{candidate_id} archive-entry manifest schema mismatch")
    expected = _manifest_entries(item["entries"], label=f"{candidate_id} archive-entry manifest", code="ARCHIVE_MANIFEST_INVALID")
    observed = _parse_ustar(archive_bytes, candidate_id=candidate_id)
    if expected != observed:
        raise fail("ARCHIVE_MANIFEST_MISMATCH", f"{candidate_id} archive bytes do not match the canonical entry manifest")
    return root, observed


def _verify_dual(item: Mapping[str, Any], *, policy: ValidatedV631Policy, domain: bytes, label: str, exclude_evidence_root: bool = False) -> dict[str, Any]:
    if item["policy_sha256"] != policy["sha256"]:
        raise fail("POPULATION_POLICY_MISMATCH", f"{label} is not bound to the validated candidate policy")
    core = {key: item[key] for key in item if key != "signatures" and (not exclude_evidence_root or key != "evidence_root_sha256")}
    verify_signature_set(item["signatures"], core=core, domain=domain, identities=policy["identities"], required_party_ids=("A", "B"), code="POPULATION_SIGNATURE_INVALID")
    return core


def _argv(value: Any, label: str, *, code: str) -> tuple[str, ...]:
    if type(value) is not list or not value or len(value) > 64:
        raise fail(code, f"{label} must be a bounded nonempty argv list")
    return tuple(identifier(argument, f"{label} argument", code=code) for argument in value)


def _source_tree(artifacts: Mapping[str, bytes], root: Any, *, candidate_id: str) -> tuple[str, list[dict[str, str]]]:
    digest, parsed = _json_artifact(artifacts, root, f"{candidate_id} source tree", code="SOURCE_EVIDENCE_INVALID")
    item = exact(parsed, frozenset({"schema", "candidate_id", "entries"}), f"{candidate_id} source tree", code="SOURCE_EVIDENCE_INVALID")
    if item["schema"] != SOURCE_TREE_SCHEMA or item["candidate_id"] != candidate_id:
        raise fail("SOURCE_EVIDENCE_INVALID", f"{candidate_id} source tree identity mismatch")
    return digest, _manifest_entries(item["entries"], label=f"{candidate_id} source tree", code="SOURCE_EVIDENCE_INVALID")


def _source_history(artifacts: Mapping[str, bytes], root: Any, *, candidate_id: str, source_tree_sha256: str) -> str:
    digest, parsed = _json_artifact(artifacts, root, f"{candidate_id} source history", code="SOURCE_EVIDENCE_INVALID")
    item = exact(parsed, frozenset({"schema", "candidate_id", "source_tree_sha256", "parent_source_tree_sha256s"}), f"{candidate_id} source history", code="SOURCE_EVIDENCE_INVALID")
    parents = canonical_string_list(item["parent_source_tree_sha256s"], f"{candidate_id} parent trees", code="SOURCE_EVIDENCE_INVALID", allow_empty=True)
    if item["schema"] != SOURCE_HISTORY_SCHEMA or item["candidate_id"] != candidate_id or item["source_tree_sha256"] != source_tree_sha256:
        raise fail("SOURCE_EVIDENCE_INVALID", f"{candidate_id} source history does not bind its source tree")
    for parent in parents:
        sha256(parent, f"{candidate_id} parent source tree", code="SOURCE_EVIDENCE_INVALID")
    return digest


def _build_recipe(artifacts: Mapping[str, bytes], root: Any, *, candidate_id: str) -> tuple[str, tuple[str, ...]]:
    digest, parsed = _json_artifact(artifacts, root, f"{candidate_id} build recipe", code="BUILD_EVIDENCE_INVALID")
    item = exact(parsed, frozenset({"schema", "candidate_id", "operating_system", "architecture", "command_argv", "output_archive_format"}), f"{candidate_id} build recipe", code="BUILD_EVIDENCE_INVALID")
    argv = _argv(item["command_argv"], f"{candidate_id} build recipe", code="BUILD_EVIDENCE_INVALID")
    if item["schema"] != BUILD_RECIPE_SCHEMA or item["candidate_id"] != candidate_id or item["operating_system"] != "linux" or item["architecture"] != "amd64" or item["output_archive_format"] != "ustar+single-gzip-member":
        raise fail("BUILD_EVIDENCE_INVALID", f"{candidate_id} build recipe is not the Linux/amd64 canonical archive profile")
    return digest, argv


def _toolchain(artifacts: Mapping[str, bytes], root: Any, *, candidate_id: str) -> str:
    digest, parsed = _json_artifact(artifacts, root, f"{candidate_id} toolchain lock", code="BUILD_EVIDENCE_INVALID")
    item = exact(parsed, frozenset({"schema", "operating_system", "architecture", "packages"}), f"{candidate_id} toolchain lock", code="BUILD_EVIDENCE_INVALID")
    if item["schema"] != TOOLCHAIN_LOCK_SCHEMA or item["operating_system"] != "linux" or item["architecture"] != "amd64" or type(item["packages"]) is not list or not item["packages"]:
        raise fail("BUILD_EVIDENCE_INVALID", f"{candidate_id} toolchain lock profile mismatch")
    packages: list[tuple[str, str, str]] = []
    for index, raw in enumerate(item["packages"]):
        package = exact(raw, frozenset({"name", "version", "artifact_sha256"}), f"{candidate_id} toolchain package {index}", code="BUILD_EVIDENCE_INVALID")
        packages.append((identifier(package["name"], "toolchain package name", code="BUILD_EVIDENCE_INVALID"), identifier(package["version"], "toolchain package version", code="BUILD_EVIDENCE_INVALID"), sha256(package["artifact_sha256"], "toolchain package hash", code="BUILD_EVIDENCE_INVALID")))
    if packages != sorted(packages) or len(set(packages)) != len(packages):
        raise fail("BUILD_EVIDENCE_INVALID", f"{candidate_id} toolchain packages must be canonical")
    return digest


def _container(artifacts: Mapping[str, bytes], root: Any, *, candidate_id: str) -> str:
    digest, parsed = _json_artifact(artifacts, root, f"{candidate_id} container profile", code="BUILD_EVIDENCE_INVALID")
    item = exact(parsed, frozenset({"schema", "operating_system", "architecture", "image_reference", "image_digest_sha256"}), f"{candidate_id} container profile", code="BUILD_EVIDENCE_INVALID")
    if item["schema"] != CONTAINER_PROFILE_SCHEMA or item["operating_system"] != "linux" or item["architecture"] != "amd64":
        raise fail("BUILD_EVIDENCE_INVALID", f"{candidate_id} container profile mismatch")
    identifier(item["image_reference"], "container image reference", code="BUILD_EVIDENCE_INVALID")
    sha256(item["image_digest_sha256"], "container image digest", code="BUILD_EVIDENCE_INVALID")
    return digest


def _named_profile(artifacts: Mapping[str, bytes], root: Any, *, candidate_id: str, schema: str, label: str) -> str:
    digest, parsed = _json_artifact(artifacts, root, f"{candidate_id} {label}", code="BUILD_EVIDENCE_INVALID")
    item = exact(parsed, frozenset({"schema", "name", "version", "content_sha256"}), f"{candidate_id} {label}", code="BUILD_EVIDENCE_INVALID")
    if item["schema"] != schema:
        raise fail("BUILD_EVIDENCE_INVALID", f"{candidate_id} {label} schema mismatch")
    identifier(item["name"], f"{label} name", code="BUILD_EVIDENCE_INVALID")
    identifier(item["version"], f"{label} version", code="BUILD_EVIDENCE_INVALID")
    sha256(item["content_sha256"], f"{label} content hash", code="BUILD_EVIDENCE_INVALID")
    return digest


def _candidate_records(artifacts: Mapping[str, bytes], root: Any, *, candidate_id: str, schema: str, label: str) -> str:
    digest, parsed = _json_artifact(artifacts, root, f"{candidate_id} {label}", code="SEMANTIC_DISCLOSURE_INVALID")
    item = exact(parsed, frozenset({"schema", "candidate_id", "record_ids"}), f"{candidate_id} {label}", code="SEMANTIC_DISCLOSURE_INVALID")
    canonical_string_list(item["record_ids"], f"{candidate_id} {label} records", code="SEMANTIC_DISCLOSURE_INVALID", allow_empty=True)
    if item["schema"] != schema or item["candidate_id"] != candidate_id:
        raise fail("SEMANTIC_DISCLOSURE_INVALID", f"{candidate_id} {label} identity mismatch")
    return digest


def _escrow_receipt(artifacts: Mapping[str, bytes], root: Any, *, candidate_id: str, source_tree_sha256: str) -> str:
    digest, parsed = _json_artifact(artifacts, root, f"{candidate_id} escrow receipt", code="SEMANTIC_DISCLOSURE_INVALID")
    item = exact(parsed, frozenset({"schema", "candidate_id", "auditor_ids", "source_tree_sha256"}), f"{candidate_id} escrow receipt", code="SEMANTIC_DISCLOSURE_INVALID")
    auditors = canonical_string_list(item["auditor_ids"], f"{candidate_id} escrow auditors", code="SEMANTIC_DISCLOSURE_INVALID", expected_count=2)
    if item["schema"] != ESCROW_RECEIPT_SCHEMA or item["candidate_id"] != candidate_id or auditors != ("A", "B") or item["source_tree_sha256"] != source_tree_sha256:
        raise fail("SEMANTIC_DISCLOSURE_INVALID", f"{candidate_id} escrow receipt binding mismatch")
    return digest


def _safety_audit(artifacts: Mapping[str, bytes], root: Any, *, candidate_id: str, auditor_id: str) -> str:
    digest, parsed = _json_artifact(artifacts, root, f"{candidate_id} {auditor_id} safety audit", code="SAFETY_AUDIT_INVALID")
    item = exact(parsed, frozenset({"schema", "candidate_id", "auditor_id", "checks"}), f"{candidate_id} {auditor_id} safety audit", code="SAFETY_AUDIT_INVALID")
    if item["schema"] != SAFETY_AUDIT_SCHEMA or item["candidate_id"] != candidate_id or item["auditor_id"] != auditor_id or type(item["checks"]) is not list:
        raise fail("SAFETY_AUDIT_INVALID", f"{candidate_id} {auditor_id} safety audit identity mismatch")
    check_ids: list[str] = []
    for index, raw in enumerate(item["checks"]):
        check = exact(raw, frozenset({"check_id", "finding_ids"}), f"{candidate_id} {auditor_id} safety check {index}", code="SAFETY_AUDIT_INVALID")
        check_ids.append(identifier(check["check_id"], "safety check id", code="SAFETY_AUDIT_INVALID"))
        findings = canonical_string_list(check["finding_ids"], "safety finding ids", code="SAFETY_AUDIT_INVALID", allow_empty=True)
        if findings:
            raise fail("SAFETY_AUDIT_FAILED", f"{candidate_id} {auditor_id} safety audit contains findings")
    if tuple(check_ids) != REQUIRED_SAFETY_CHECK_IDS:
        raise fail("SAFETY_AUDIT_INVALID", f"{candidate_id} {auditor_id} safety audit lacks the exact required checks")
    return digest


def _archive(value: Any, *, candidate_id: str, artifacts: Mapping[str, bytes]) -> dict[str, Any]:
    item = exact(value, _ARCHIVE_FIELDS, f"{candidate_id} archive", code="POPULATION_EVIDENCE_INVALID")
    if item["schema"] != ARCHIVE_EVIDENCE_SCHEMA:
        raise fail("POPULATION_EVIDENCE_INVALID", f"{candidate_id} archive schema mismatch")
    filename = identifier(item["archive_filename"], f"{candidate_id} archive filename", code="POPULATION_EVIDENCE_INVALID")
    if not filename.endswith(".tar.gz") or "/" in filename or "\\" in filename:
        raise fail("POPULATION_EVIDENCE_INVALID", f"{candidate_id} archive filename must be a bare .tar.gz filename")
    length = canonical_integer(item["archive_byte_length"], f"{candidate_id} archive length", code="POPULATION_EVIDENCE_INVALID", minimum=1)
    archive_sha = _payload(artifacts, item["archive_sha256"], f"{candidate_id} archive")
    if len(artifacts[archive_sha]) != length:
        raise fail("ARCHIVE_LENGTH_MISMATCH", f"{candidate_id} archive length does not match payload")
    manifest_root = _payload(artifacts, item["archive_entry_manifest_sha256"], f"{candidate_id} archive manifest")
    manifest_root, entries = _archive_manifest(artifacts, manifest_root, artifacts[archive_sha], candidate_id=candidate_id)
    core = {"schema": ARCHIVE_EVIDENCE_SCHEMA, "archive_filename": filename, "archive_byte_length": item["archive_byte_length"], "archive_sha256": archive_sha, "archive_entry_manifest_sha256": manifest_root}
    root = _canonical_payload(artifacts, item["evidence_root_sha256"], f"{candidate_id} archive root", core)
    return {**core, "archive_byte_length_int": length, "entries": entries, "evidence_root_sha256": root}


def _package(value: Any, *, candidate_id: str, artifacts: Mapping[str, bytes], archive: Mapping[str, Any]) -> dict[str, Any]:
    item = exact(value, _PACKAGE_FIELDS, f"{candidate_id} package", code="POPULATION_EVIDENCE_INVALID")
    if item["schema"] != PACKAGE_EVIDENCE_SCHEMA:
        raise fail("POPULATION_EVIDENCE_INVALID", f"{candidate_id} package schema mismatch")
    archive_sha = _payload(artifacts, item["archive_sha256"], f"{candidate_id} package archive")
    manifest = _payload(artifacts, item["archive_entry_manifest_sha256"], f"{candidate_id} package manifest")
    source_tree, source_entries = _source_tree(artifacts, item["source_tree_sha256"], candidate_id=candidate_id)
    recipe, argv = _build_recipe(artifacts, item["build_recipe_sha256"], candidate_id=candidate_id)
    length = canonical_integer(item["archive_byte_length"], f"{candidate_id} package length", code="POPULATION_EVIDENCE_INVALID", minimum=1)
    if archive_sha != archive["archive_sha256"] or manifest != archive["archive_entry_manifest_sha256"] or length != archive["archive_byte_length_int"]:
        raise fail("ARCHIVE_PACKAGE_MISMATCH", f"{candidate_id} package does not close over archive bytes")
    core = {"schema": PACKAGE_EVIDENCE_SCHEMA, "archive_sha256": archive_sha, "archive_byte_length": item["archive_byte_length"], "archive_entry_manifest_sha256": manifest, "source_tree_sha256": source_tree, "build_recipe_sha256": recipe}
    root = _canonical_payload(artifacts, item["package_root_sha256"], f"{candidate_id} package root", core)
    return {**core, "source_entries": source_entries, "build_command_argv": argv, "package_root_sha256": root}


def _source(value: Any, *, candidate_id: str, artifacts: Mapping[str, bytes], package: Mapping[str, Any], policy: ValidatedV631Policy) -> dict[str, str]:
    item = exact(value, _SOURCE_FIELDS, f"{candidate_id} source", code="SOURCE_EVIDENCE_INVALID")
    if item["schema"] != SOURCE_EVIDENCE_SCHEMA or item["source_mode"] not in SOURCE_MODES:
        raise fail("SOURCE_EVIDENCE_INVALID", f"{candidate_id} source schema or mode invalid")
    core = _verify_dual(item, policy=policy, domain=DOMAIN_SOURCE_EVIDENCE, label=f"{candidate_id} source", exclude_evidence_root=True)
    source_tree, _ = _source_tree(artifacts, item["source_tree_sha256"], candidate_id=candidate_id)
    if source_tree != package["source_tree_sha256"]:
        raise fail("SOURCE_EVIDENCE_INVALID", f"{candidate_id} source tree does not match package")
    history = _source_history(artifacts, item["source_history_root_sha256"], candidate_id=candidate_id, source_tree_sha256=source_tree)
    a_plaintext = _payload(artifacts, item["auditor_a_plaintext_root_sha256"], f"{candidate_id} auditor A source tree")
    b_plaintext = _payload(artifacts, item["auditor_b_plaintext_root_sha256"], f"{candidate_id} auditor B source tree")
    if a_plaintext != source_tree or b_plaintext != source_tree:
        raise fail("SOURCE_ESCROW_INCOMPLETE", f"{candidate_id} A/B plaintext roots must equal the typed source tree")
    roots = {"source_tree_sha256": source_tree, "source_history_root_sha256": history, "auditor_a_plaintext_root_sha256": a_plaintext, "auditor_b_plaintext_root_sha256": b_plaintext}
    root = _canonical_payload(artifacts, item["evidence_root_sha256"], f"{candidate_id} source root", {**core, **roots})
    return {**roots, "source_mode": item["source_mode"], "evidence_root_sha256": root}


def _rebuild_receipts(value: Any, *, candidate_id: str, archive: Mapping[str, Any], package: Mapping[str, Any], build_roots: Mapping[str, str], artifacts: Mapping[str, bytes], policy: ValidatedV631Policy) -> tuple[str, ...]:
    if type(value) is not list or len(value) != 2:
        raise fail("REBUILD_RECEIPT_INVALID", f"{candidate_id} requires A/B Linux/amd64 rebuild receipts")
    auditors: list[str] = []
    for expected_auditor, raw in zip(("A", "B"), value, strict=True):
        item = exact(raw, _REBUILD_RECEIPT_FIELDS, f"{candidate_id} {expected_auditor} rebuild receipt", code="REBUILD_RECEIPT_INVALID")
        if item["schema"] != REBUILD_RECEIPT_SCHEMA or item["auditor_id"] != expected_auditor or item["policy_sha256"] != policy["sha256"]:
            raise fail("REBUILD_RECEIPT_INVALID", f"{candidate_id} {expected_auditor} rebuild receipt identity mismatch")
        receipt_core = {key: item[key] for key in item if key != "signature"}
        verify_signature_set([item["signature"]], core=receipt_core, domain=DOMAIN_REBUILD_RECEIPT, identities=policy["identities"], required_party_ids=(expected_auditor,), code="REBUILD_RECEIPT_INVALID")
        argv = _argv(item["rebuild_command_argv"], f"{candidate_id} {expected_auditor} rebuild command", code="REBUILD_RECEIPT_INVALID")
        length = canonical_integer(item["output_archive_byte_length"], f"{candidate_id} {expected_auditor} output archive length", code="REBUILD_RECEIPT_INVALID", minimum=1)
        expected = {
            "operating_system": "linux",
            "architecture": "amd64",
            "rebuild_command_argv": package["build_command_argv"],
            "build_recipe_sha256": package["build_recipe_sha256"],
            "source_tree_sha256": package["source_tree_sha256"],
            "toolchain_lock_sha256": build_roots["toolchain_lock_sha256"],
            "container_image_sha256": build_roots["container_image_sha256"],
            "engine_sha256": build_roots["engine_sha256"],
            "ruleset_sha256": build_roots["ruleset_sha256"],
            "output_archive_sha256": archive["archive_sha256"],
            "output_archive_byte_length": archive["archive_byte_length_int"],
            "output_archive_entry_manifest_sha256": archive["archive_entry_manifest_sha256"],
        }
        if (
            item["operating_system"] != expected["operating_system"]
            or item["architecture"] != expected["architecture"]
            or argv != expected["rebuild_command_argv"]
            or length != expected["output_archive_byte_length"]
            or any(item[field] != expected[field] for field in expected if field not in {"operating_system", "architecture", "rebuild_command_argv", "output_archive_byte_length"})
        ):
            raise fail("REBUILD_RECEIPT_INVALID", f"{candidate_id} {expected_auditor} rebuild receipt does not exactly reproduce the canonical inputs and output")
        _safety_audit(artifacts, item["safety_audit_root_sha256"], candidate_id=candidate_id, auditor_id=expected_auditor)
        auditors.append(expected_auditor)
    return tuple(auditors)


def _build(value: Any, *, candidate_id: str, artifacts: Mapping[str, bytes], archive: Mapping[str, Any], package: Mapping[str, Any], source: Mapping[str, str], policy: ValidatedV631Policy) -> dict[str, Any]:
    item = exact(value, _BUILD_FIELDS, f"{candidate_id} build", code="BUILD_EVIDENCE_INVALID")
    if item["schema"] != BUILD_EVIDENCE_SCHEMA:
        raise fail("BUILD_EVIDENCE_INVALID", f"{candidate_id} build schema mismatch")
    core = _verify_dual(item, policy=policy, domain=DOMAIN_BUILD_EVIDENCE, label=f"{candidate_id} build", exclude_evidence_root=True)
    package_root = _payload(artifacts, item["package_root_sha256"], f"{candidate_id} package root")
    source_root = _payload(artifacts, item["source_evidence_root_sha256"], f"{candidate_id} source evidence root")
    recipe, _ = _build_recipe(artifacts, item["build_recipe_sha256"], candidate_id=candidate_id)
    toolchain = _toolchain(artifacts, item["toolchain_lock_sha256"], candidate_id=candidate_id)
    container = _container(artifacts, item["container_image_sha256"], candidate_id=candidate_id)
    engine = _named_profile(artifacts, item["engine_sha256"], candidate_id=candidate_id, schema=ENGINE_PROFILE_SCHEMA, label="engine profile")
    ruleset = _named_profile(artifacts, item["ruleset_sha256"], candidate_id=candidate_id, schema=RULESET_PROFILE_SCHEMA, label="ruleset profile")
    roots = {"package_root_sha256": package_root, "source_evidence_root_sha256": source_root, "build_recipe_sha256": recipe, "toolchain_lock_sha256": toolchain, "container_image_sha256": container, "engine_sha256": engine, "ruleset_sha256": ruleset}
    if package_root != package["package_root_sha256"] or source_root != source["evidence_root_sha256"] or recipe != package["build_recipe_sha256"]:
        raise fail("BUILD_EVIDENCE_INVALID", f"{candidate_id} build does not close over package and source")
    receipt_auditors = _rebuild_receipts(item["rebuild_receipts"], candidate_id=candidate_id, archive=archive, package=package, build_roots=roots, artifacts=artifacts, policy=policy)
    root = _canonical_payload(artifacts, item["evidence_root_sha256"], f"{candidate_id} build root", {**core, **roots})
    return {**roots, "receipt_auditor_ids": receipt_auditors, "evidence_root_sha256": root}


def _semantic_disclosure(value: Any, *, candidate_id: str, artifacts: Mapping[str, bytes], source_tree_sha256: str, policy: ValidatedV631Policy) -> dict[str, Any]:
    item = exact(value, _SEMANTIC_DISCLOSURE_FIELDS, f"{candidate_id} candidate disclosure", code="SEMANTIC_DISCLOSURE_INVALID")
    if item["schema"] != SEMANTIC_DISCLOSURE_SCHEMA:
        raise fail("SEMANTIC_DISCLOSURE_INVALID", f"{candidate_id} candidate disclosure schema mismatch")
    core = _verify_dual(item, policy=policy, domain=DOMAIN_SEMANTIC_DISCLOSURE, label=f"{candidate_id} candidate disclosure", exclude_evidence_root=True)
    principals = canonical_string_list(item["declared_principal_ids"], f"{candidate_id} declared principals", code="SEMANTIC_DISCLOSURE_INVALID")
    specifications = (
        ("control_evidence_root_sha256", CONTROL_EVIDENCE_SCHEMA, "candidate control evidence"),
        ("ancestry_root_sha256", ANCESTRY_EVIDENCE_SCHEMA, "candidate ancestry evidence"),
        ("forks_root_sha256", FORKS_EVIDENCE_SCHEMA, "candidate forks evidence"),
        ("third_party_inputs_root_sha256", THIRD_PARTY_INPUTS_SCHEMA, "candidate third-party inputs"),
        ("intervention_evidence_root_sha256", INTERVENTION_EVIDENCE_SCHEMA, "candidate intervention evidence"),
    )
    roots = {field: _candidate_records(artifacts, item[field], candidate_id=candidate_id, schema=schema, label=label) for field, schema, label in specifications}
    roots["escrow_receipt_root_sha256"] = _escrow_receipt(artifacts, item["escrow_receipt_root_sha256"], candidate_id=candidate_id, source_tree_sha256=source_tree_sha256)
    precommit = {"schema": CONTRIBUTOR_CHALLENGE_PRECOMMIT_SCHEMA, "candidate_id": candidate_id, "declared_principal_ids": list(principals)}
    challenge = _canonical_payload(artifacts, item["contributor_challenge_precommit_sha256"], f"{candidate_id} contributor challenge precommit", precommit)
    expected = {**core, "declared_principal_ids": list(principals), **roots, "contributor_challenge_precommit_sha256": challenge}
    root = _canonical_payload(artifacts, item["evidence_root_sha256"], f"{candidate_id} candidate disclosure root", expected)
    return {"evidence_root_sha256": root, "contributor_challenge_precommit_sha256": challenge}


def _unit(value: Any, *, candidate_id: str, artifacts: Mapping[str, bytes], policy: ValidatedV631Policy) -> dict[str, Any]:
    item = exact(value, _UNIT_FIELDS, f"candidate {candidate_id}", code="POPULATION_EVIDENCE_INVALID")
    if item["schema"] != UNIT_SCHEMA or item["candidate_id"] != candidate_id:
        raise fail("CANDIDATE_ID_INVALID", "units must use exact canonical U01-U16 order")
    archive = _archive(item["archive"], candidate_id=candidate_id, artifacts=artifacts)
    package = _package(item["package"], candidate_id=candidate_id, artifacts=artifacts, archive=archive)
    source = _source(item["source"], candidate_id=candidate_id, artifacts=artifacts, package=package, policy=policy)
    build = _build(item["build"], candidate_id=candidate_id, artifacts=artifacts, archive=archive, package=package, source=source, policy=policy)
    disclosure = _semantic_disclosure(item["semantic_disclosure"], candidate_id=candidate_id, artifacts=artifacts, source_tree_sha256=source["source_tree_sha256"], policy=policy)
    core = {"schema": UNIT_SCHEMA, "candidate_id": candidate_id, "archive_evidence_root_sha256": archive["evidence_root_sha256"], "package_root_sha256": package["package_root_sha256"], "source_evidence_root_sha256": source["evidence_root_sha256"], "build_evidence_root_sha256": build["evidence_root_sha256"], "semantic_disclosure_evidence_root_sha256": disclosure["evidence_root_sha256"]}
    root = _canonical_payload(artifacts, item["evidence_root_sha256"], f"{candidate_id} unit root", core)
    return {"archive_sha256": archive["archive_sha256"], "archive_byte_length": archive["archive_byte_length_int"], "archive_filename": archive["archive_filename"], "archive_entry_manifest_sha256": archive["archive_entry_manifest_sha256"], "package_root_sha256": package["package_root_sha256"], "source_tree_sha256": source["source_tree_sha256"], "build_evidence_root_sha256": build["evidence_root_sha256"], "candidate_disclosure_evidence_root_sha256": disclosure["evidence_root_sha256"], "linux_amd64_rebuild_receipt_auditor_ids": build["receipt_auditor_ids"], "evidence_root_sha256": root}


def _pair_review(artifacts: Mapping[str, bytes], root: Any, *, left: str, right: str, auditor_id: str, review_kind: str) -> str:
    digest, parsed = _json_artifact(artifacts, root, f"{left}/{right} {auditor_id} {review_kind} review", code="PAIR_CLASSIFICATION_INVALID")
    item = exact(parsed, frozenset({"schema", "auditor_id", "left_candidate_id", "right_candidate_id", "review_kind", "observation_ids"}), f"{left}/{right} {auditor_id} {review_kind} review", code="PAIR_CLASSIFICATION_INVALID")
    canonical_string_list(item["observation_ids"], "pair review observations", code="PAIR_CLASSIFICATION_INVALID", allow_empty=True)
    if item["schema"] != PAIR_REVIEW_EVIDENCE_SCHEMA or item["auditor_id"] != auditor_id or item["left_candidate_id"] != left or item["right_candidate_id"] != right or item["review_kind"] != review_kind:
        raise fail("PAIR_CLASSIFICATION_INVALID", f"{left}/{right} pair review binding mismatch")
    return digest


def _classification(value: Any, *, left: str, right: str, artifacts: Mapping[str, bytes]) -> None:
    item = exact(value, _AUDITOR_CLASSIFICATION_FIELDS, f"{left}/{right} classification", code="PAIR_CLASSIFICATION_INVALID")
    if item["schema"] != AUDITOR_CLASSIFICATION_SCHEMA or item["auditor_id"] not in {"A", "B"}:
        raise fail("PAIR_CLASSIFICATION_INVALID", f"{left}/{right} classification identity invalid")
    if any(item[field] not in SOURCE_LINEAGE_STATES for field in ("source_state", "lineage_control_state", "development_control_state")) or item["intervention_state"] not in INTERVENTION_STATES:
        raise fail("PAIR_CLASSIFICATION_INVALID", f"{left}/{right} classification state invalid")
    review_fields = (
        ("source_review_root_sha256", "source"),
        ("lineage_control_review_root_sha256", "lineage_control"),
        ("development_control_review_root_sha256", "development_control"),
        ("intervention_review_root_sha256", "intervention"),
    )
    review_roots = {field: _pair_review(artifacts, item[field], left=left, right=right, auditor_id=item["auditor_id"], review_kind=kind) for field, kind in review_fields}
    evidence = {"schema": PAIR_ANALYSIS_EVIDENCE_SCHEMA, "auditor_id": item["auditor_id"], "left_candidate_id": left, "right_candidate_id": right, **review_roots}
    evidence_root = _canonical_payload(artifacts, item["analysis_evidence_root_sha256"], f"{left}/{right} candidate analysis evidence", evidence)
    analysis = {"schema": PAIR_ANALYSIS_SCHEMA, "auditor_id": item["auditor_id"], "left_candidate_id": left, "right_candidate_id": right, "source_state": item["source_state"], "lineage_control_state": item["lineage_control_state"], "development_control_state": item["development_control_state"], "intervention_state": item["intervention_state"], "analysis_evidence_root_sha256": evidence_root}
    _canonical_payload(artifacts, item["analysis_root_sha256"], f"{left}/{right} candidate analysis", analysis)


def _pair_classifications(value: Any, *, artifacts: Mapping[str, bytes], policy: ValidatedV631Policy) -> int:
    required = _required_pairs()
    if type(value) is not list or len(value) != len(required):
        raise fail("PAIR_CLASSIFICATION_INCOMPLETE", "exactly 120 canonical candidate pairs are required")
    for expected, raw in zip(required, value, strict=True):
        left, right = expected
        item = exact(raw, _PAIR_FIELDS, f"pair {left}/{right}", code="PAIR_CLASSIFICATION_INVALID")
        if item["schema"] != PAIR_CLASSIFICATION_SCHEMA or (item["left_candidate_id"], item["right_candidate_id"]) != expected:
            raise fail("PAIR_CLASSIFICATION_INVALID", "pair order or schema invalid")
        _verify_dual(item, policy=policy, domain=DOMAIN_PAIR_CLASSIFICATION, label=f"pair {left}/{right}")
        if type(item["classifications"]) is not list or len(item["classifications"]) != 2:
            raise fail("PAIR_CLASSIFICATION_INCOMPLETE", f"{left}/{right} requires A/B candidate classifications")
        if tuple(classification.get("auditor_id") for classification in item["classifications"] if type(classification) is dict) != ("A", "B"):
            raise fail("PAIR_CLASSIFICATION_INCOMPLETE", f"{left}/{right} classifications must be A then B")
        for classification in item["classifications"]:
            _classification(classification, left=left, right=right, artifacts=artifacts)
    return len(required)


def validate_candidate_population(value: Any, *, policy: ValidatedV631Policy) -> ValidatedCandidatePopulation:
    """Validate neutral G2 content and candidate-key conformance only."""
    policy = require_validated_policy(policy)
    item = exact(value, _POPULATION_FIELDS, "G2 candidate population", code="POPULATION_EVIDENCE_INVALID")
    if item["schema"] != POPULATION_SCHEMA:
        raise fail("POPULATION_EVIDENCE_INVALID", "G2 candidate population schema mismatch")
    artifacts = _artifacts(item["artifacts"])
    if type(item["units"]) is not list or len(item["units"]) != len(CANDIDATE_IDS):
        raise fail("CANDIDATE_ID_INVALID", "G2 requires exactly U01-U16")
    units = {candidate: _unit(raw, candidate_id=candidate, artifacts=artifacts, policy=policy) for candidate, raw in zip(CANDIDATE_IDS, item["units"], strict=True)}
    archive_hashes = tuple(units[candidate]["archive_sha256"] for candidate in CANDIDATE_IDS)
    if len(set(archive_hashes)) != len(CANDIDATE_IDS):
        raise fail("ARCHIVE_IDENTITY_COLLISION", "all 16 candidates require distinct archive hashes")
    if archive_hashes != tuple(sorted(archive_hashes)):
        raise fail("CANDIDATE_ARCHIVE_ORDER_INVALID", "U01-U16 must be assigned by strictly ascending lowercase archive sha256")
    pair_root = _canonical_payload(artifacts, item["pair_classifications_root_sha256"], "candidate pair classifications root", item["pair_classifications"])
    pair_count = _pair_classifications(item["pair_classifications"], artifacts=artifacts, policy=policy)
    evidence_core = {"schema": "eval.v6.3.1.g2-candidate-population-evidence", "policy_sha256": policy["sha256"], "unit_evidence_root_sha256s": [units[candidate]["evidence_root_sha256"] for candidate in CANDIDATE_IDS], "pair_classifications_root_sha256": pair_root}
    evidence_root = _canonical_payload(artifacts, item["evidence_root_sha256"], "G2 candidate population root", evidence_core)
    result = {
        "schema": VALIDATED_POPULATION_SCHEMA,
        "candidate_policy_sha256": policy["sha256"],
        "population_evidence_root_sha256": evidence_root,
        "archive_hashes_by_candidate_id": {candidate: archive_hash for candidate, archive_hash in zip(CANDIDATE_IDS, archive_hashes, strict=True)},
        "units": units,
        "candidate_pair_classification_attachment": {
            "root_sha256": pair_root,
            "pair_count": pair_count,
            "candidate_policy_signatures_structurally_verified": True,
            "semantic_interpretation_performed": False,
            "externally_authenticated": False,
        },
        "schema_conformant_only": True,
        "semantic_population_closed": False,
        "semantic_population_validated": False,
    }
    retained_data = freeze(result)
    validated = ValidatedCandidatePopulation(retained_data, _VALIDATED_SENTINEL)
    _register_issued_population(validated, retained_data)
    return validated


def offline_population_verdict(value: ValidatedCandidatePopulation) -> Mapping[str, Any]:
    retained = _require_issued_population(value)
    report = zero_authority(
        "V631_G2_CANDIDATE_SCHEMA_CONFORMANT_ONLY",
        detail="G2 establishes only canonical candidate content and candidate-policy signature conformance; no semantic graph, external typed roster, role assignment, campaign root, or fresh post-drand response is present.",
        extra={
            "candidate_policy_sha256": retained["candidate_policy_sha256"],
            "population_evidence_root_sha256": retained["population_evidence_root_sha256"],
            "schema_conformant_only": True,
            "semantic_population_closed": False,
            "semantic_population_validated": False,
        },
    )
    report["schema"] = VERDICT_SCHEMA
    return freeze(report)


def assess_candidate_population(value: Any, *, policy: ValidatedV631Policy) -> Mapping[str, Any]:
    return offline_population_verdict(validate_candidate_population(value, policy=policy))


__all__ = [
    "ANCESTRY_EVIDENCE_SCHEMA",
    "ARCHIVE_ENTRY_MANIFEST_SCHEMA",
    "ARCHIVE_EVIDENCE_SCHEMA",
    "ARTIFACT_SCHEMA",
    "AUDITOR_CLASSIFICATION_SCHEMA",
    "BUILD_EVIDENCE_SCHEMA",
    "BUILD_RECIPE_SCHEMA",
    "CANDIDATE_IDS",
    "CONTAINER_PROFILE_SCHEMA",
    "CONTRIBUTOR_CHALLENGE_PRECOMMIT_SCHEMA",
    "CONTROL_EVIDENCE_SCHEMA",
    "DOMAIN_BUILD_EVIDENCE",
    "DOMAIN_PAIR_CLASSIFICATION",
    "DOMAIN_REBUILD_RECEIPT",
    "DOMAIN_SEMANTIC_DISCLOSURE",
    "DOMAIN_SOURCE_EVIDENCE",
    "ENGINE_PROFILE_SCHEMA",
    "ESCROW_RECEIPT_SCHEMA",
    "FORKS_EVIDENCE_SCHEMA",
    "INTERVENTION_EVIDENCE_SCHEMA",
    "INTERVENTION_STATES",
    "MAX_ARCHIVE_ENTRIES",
    "PACKAGE_EVIDENCE_SCHEMA",
    "PAIR_ANALYSIS_EVIDENCE_SCHEMA",
    "PAIR_ANALYSIS_SCHEMA",
    "PAIR_CLASSIFICATION_SCHEMA",
    "PAIR_REVIEW_EVIDENCE_SCHEMA",
    "POPULATION_SCHEMA",
    "REBUILD_RECEIPT_SCHEMA",
    "REQUIRED_SAFETY_CHECK_IDS",
    "RULESET_PROFILE_SCHEMA",
    "SAFETY_AUDIT_SCHEMA",
    "SEMANTIC_DISCLOSURE_SCHEMA",
    "SOURCE_EVIDENCE_SCHEMA",
    "SOURCE_HISTORY_SCHEMA",
    "SOURCE_LINEAGE_STATES",
    "SOURCE_MODES",
    "SOURCE_TREE_SCHEMA",
    "THIRD_PARTY_INPUTS_SCHEMA",
    "TOOLCHAIN_LOCK_SCHEMA",
    "UNIT_SCHEMA",
    "VALIDATED_POPULATION_SCHEMA",
    "VERDICT_SCHEMA",
    "ValidatedCandidatePopulation",
    "assess_candidate_population",
    "offline_population_verdict",
    "validate_candidate_population",
]
