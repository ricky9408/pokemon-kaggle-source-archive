"""Fail-closed, outcome-free population readiness for governance v4.2.

This module does not build the final population manifest and cannot authorize
Kaggle work.  It proves the filesystem and provenance prerequisites that must
exist before the population may be timestamped.  In particular, ancestry IDs
and family labels are derived here; callers cannot provide them.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
import keyword
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import tokenize
from typing import Any, Iterable, Mapping
import uuid

from evaluation_v2.package import build_archive
from evaluation_v4.lineage import (
    ancestry_id_for_roots,
    inspect_archive,
    lineage_id_for_archive,
)

CANDIDATE_GRAMMAR_SCHEMA = "evaluation_v4_2_candidate_grammar_v1"
FAMILY_ONTOLOGY_SCHEMA = "evaluation_v4_2_family_ontology_v1"
ELIGIBILITY_SCHEMA = "evaluation_v4_2_lineage_eligibility_v1"
CONTEXT_MANIFEST_SCHEMA = "evaluation_v4_2_isolated_context_manifest_v1"
ROOT_RECEIPT_SCHEMA = "evaluation_v4_2_isolated_root_receipt_v1"
ROSTER_SCHEMA = "evaluation_v4_2_population_roster_v1"
READINESS_SCHEMA = "evaluation_v4_2_population_readiness_v1"

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_FAMILY_RE = re.compile(r"^deck-family-[a-z0-9]+(?:-[a-z0-9]+)*$")
_PROVENANCE_NAME_TOKENS = frozenset({"author", "claude", "codex", "grok", "player", "team"})
_CONTEXT_ROLES = frozenset(
    {"cards_reference", "competition_rules", "engine_api", "family_spec", "prompt"}
)
_REQUIRED_ROOT_FILES = ["deck.csv", "main.py"]
_REQUIRED_ENGINE_FILES = ["cg/api.py", "cg/libcg.so"]
_ALLOWED_GENERATION_MODES = ["isolated_clean_room_v1"]

_GRAMMAR_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "grammar_id",
        "required_root_files",
        "required_engine_files",
        "allowed_generation_modes",
        "forbid_outcome_conditioning",
        "require_isolated_context",
        "state",
    }
)
_GRAMMAR_FIELDS = _GRAMMAR_CONTENT_FIELDS | {"content_sha256"}
_ONTOLOGY_CONTENT_FIELDS = frozenset(
    {"schema", "ontology_id", "classification_basis", "families", "state"}
)
_ONTOLOGY_FIELDS = _ONTOLOGY_CONTENT_FIELDS | {"content_sha256"}
_FAMILY_FIELDS = frozenset({"family_id", "deck_sha256s"})
_ELIGIBILITY_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "eligibility_id",
        "candidate_grammar_sha256",
        "family_ontology_sha256",
        "trusted_orchestrator_sha256",
        "trusted_packager_sha256",
        "uuid_allocation_sha256",
        "allowed_shared_material_sha256s",
        "burned_artifact_sha256s",
        "required_population_size",
        "required_families",
        "required_per_family",
        "require_zero_parents",
        "require_unique_origin_session",
        "require_archive_source_identity",
        "maximum_policy_shingle_jaccard",
        "forbidden_context_namespaces",
        "state",
    }
)
_ELIGIBILITY_FIELDS = _ELIGIBILITY_CONTENT_FIELDS | {"content_sha256"}
_CONTEXT_CONTENT_FIELDS = frozenset(
    {"schema", "origin_session_uuid", "entries", "state"}
)
_CONTEXT_FIELDS = _CONTEXT_CONTENT_FIELDS | {"content_sha256"}
_CONTEXT_ENTRY_FIELDS = frozenset({"path", "sha256", "role"})
_RECEIPT_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "lineage_uuid",
        "origin_session_uuid",
        "generation_mode",
        "model_provider",
        "model_id",
        "model_request_id",
        "orchestrator_sha256",
        "packager_sha256",
        "uuid_allocation_sha256",
        "context_manifest_sha256",
        "source_tree_sha256",
        "archive_sha256",
        "input_artifact_sha256s",
        "human_patch_sha256s",
        "compute_receipt_sha256",
        "parent_archive_sha256s",
        "prior_hosted_submission_refs",
        "outcome_conditioned",
        "predictor_output_seen",
        "eligibility_result_seen",
        "started_at_utc",
        "finished_at_utc",
        "state",
    }
)
_RECEIPT_FIELDS = _RECEIPT_CONTENT_FIELDS | {"content_sha256"}
_ROSTER_FIELDS = frozenset(
    {
        "schema",
        "roster_id",
        "candidate_grammar_sha256",
        "eligibility_sha256",
        "family_ontology_sha256",
        "compute_budget_id",
        "records",
        "state",
    }
)
_ROSTER_RECORD_FIELDS = frozenset(
    {
        "lineage_uuid",
        "archive_path",
        "source_dir",
        "context_manifest_path",
        "root_receipt_path",
    }
)


class PopulationReadinessError(ValueError):
    """A population readiness artifact is malformed."""


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PopulationReadinessError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise PopulationReadinessError(f"{label} must be a non-empty trimmed string")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise PopulationReadinessError(f"{label} must be a lowercase SHA-256")
    return value


def _uuid(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise PopulationReadinessError(f"{label} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise PopulationReadinessError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise PopulationReadinessError(f"{label} must be a canonical UUID")
    return value


def _utc(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise PopulationReadinessError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PopulationReadinessError(f"{label} must be canonical UTC") from exc
    if parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") != value:
        raise PopulationReadinessError(f"{label} must be canonical UTC")
    return value


def _sealed(content: Mapping[str, Any]) -> dict[str, Any]:
    return {**content, "content_sha256": canonical_sha256(content)}


def _validate_sealed(
    value: object,
    *,
    content_fields: frozenset[str],
    fields: frozenset[str],
    label: str,
) -> dict[str, Any]:
    raw = _exact(value, fields, label=label)
    content = {field: raw[field] for field in content_fields}
    digest = _sha(raw["content_sha256"], label=f"{label}.content_sha256")
    if digest != canonical_sha256(content):
        raise PopulationReadinessError(f"{label} content_sha256 mismatch")
    return {**content, "content_sha256": digest}


def build_candidate_grammar(content: Mapping[str, Any]) -> dict[str, Any]:
    if "content_sha256" in content:
        raise PopulationReadinessError("candidate grammar builder accepts hash-free content")
    return validate_candidate_grammar(_sealed(content))


def validate_candidate_grammar(value: object) -> dict[str, Any]:
    grammar = _validate_sealed(
        value,
        content_fields=_GRAMMAR_CONTENT_FIELDS,
        fields=_GRAMMAR_FIELDS,
        label="candidate grammar",
    )
    if grammar["schema"] != CANDIDATE_GRAMMAR_SCHEMA:
        raise PopulationReadinessError("candidate grammar schema mismatch")
    _identifier(grammar["grammar_id"], label="grammar_id")
    if grammar["required_root_files"] != _REQUIRED_ROOT_FILES:
        raise PopulationReadinessError("candidate grammar required_root_files mismatch")
    if grammar["required_engine_files"] != _REQUIRED_ENGINE_FILES:
        raise PopulationReadinessError("candidate grammar required_engine_files mismatch")
    if grammar["allowed_generation_modes"] != _ALLOWED_GENERATION_MODES:
        raise PopulationReadinessError("candidate grammar generation modes mismatch")
    if grammar["forbid_outcome_conditioning"] is not True:
        raise PopulationReadinessError("candidate grammar must forbid outcome conditioning")
    if grammar["require_isolated_context"] is not True:
        raise PopulationReadinessError("candidate grammar must require isolated context")
    if grammar["state"] != "FROZEN":
        raise PopulationReadinessError("candidate grammar state must be FROZEN")
    return grammar


def build_family_ontology(content: Mapping[str, Any]) -> dict[str, Any]:
    if "content_sha256" in content:
        raise PopulationReadinessError("family ontology builder accepts hash-free content")
    return validate_family_ontology(_sealed(content))


def validate_family_ontology(value: object) -> dict[str, Any]:
    ontology = _validate_sealed(
        value,
        content_fields=_ONTOLOGY_CONTENT_FIELDS,
        fields=_ONTOLOGY_FIELDS,
        label="family ontology",
    )
    if ontology["schema"] != FAMILY_ONTOLOGY_SCHEMA:
        raise PopulationReadinessError("family ontology schema mismatch")
    _identifier(ontology["ontology_id"], label="ontology_id")
    if ontology["classification_basis"] != "deck_sha256_allowlist":
        raise PopulationReadinessError("family ontology must classify by deck_sha256_allowlist")
    if not isinstance(ontology["families"], list) or len(ontology["families"]) < 5:
        raise PopulationReadinessError("family ontology must contain at least five families")
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_decks: set[str] = set()
    for index, raw in enumerate(ontology["families"]):
        family = _exact(raw, _FAMILY_FIELDS, label=f"family {index}")
        family_id = _identifier(family["family_id"], label=f"family {index}.family_id")
        if _FAMILY_RE.fullmatch(family_id) is None:
            raise PopulationReadinessError("family_id must be a neutral deck-family-* identifier")
        tokens = set(family_id.split("-"))
        if tokens & _PROVENANCE_NAME_TOKENS:
            raise PopulationReadinessError("family_id must not encode author or model provenance")
        decks = family["deck_sha256s"]
        if not isinstance(decks, list) or not decks:
            raise PopulationReadinessError("each family must contain deck SHA-256 values")
        normalized_decks = sorted(_sha(item, label="deck_sha256") for item in decks)
        if len(normalized_decks) != len(set(normalized_decks)):
            raise PopulationReadinessError("family deck SHA-256 values must be unique")
        if family_id in seen_ids or seen_decks.intersection(normalized_decks):
            raise PopulationReadinessError("family IDs and deck assignments must be disjoint")
        seen_ids.add(family_id)
        seen_decks.update(normalized_decks)
        normalized.append({"family_id": family_id, "deck_sha256s": normalized_decks})
    normalized.sort(key=lambda row: row["family_id"])
    if ontology["families"] != normalized:
        raise PopulationReadinessError("family ontology families must be canonical and sorted")
    if ontology["state"] != "FROZEN":
        raise PopulationReadinessError("family ontology state must be FROZEN")
    return ontology


def build_eligibility(content: Mapping[str, Any]) -> dict[str, Any]:
    if "content_sha256" in content:
        raise PopulationReadinessError("eligibility builder accepts hash-free content")
    return validate_eligibility(_sealed(content))


def validate_eligibility(value: object) -> dict[str, Any]:
    eligibility = _validate_sealed(
        value,
        content_fields=_ELIGIBILITY_CONTENT_FIELDS,
        fields=_ELIGIBILITY_FIELDS,
        label="eligibility",
    )
    if eligibility["schema"] != ELIGIBILITY_SCHEMA:
        raise PopulationReadinessError("eligibility schema mismatch")
    _identifier(eligibility["eligibility_id"], label="eligibility_id")
    for field in (
        "candidate_grammar_sha256",
        "family_ontology_sha256",
        "trusted_orchestrator_sha256",
        "trusted_packager_sha256",
        "uuid_allocation_sha256",
    ):
        _sha(eligibility[field], label=field)
    allowed_shared = eligibility["allowed_shared_material_sha256s"]
    burned = eligibility["burned_artifact_sha256s"]
    for label, values in (("allowed_shared_material_sha256s", allowed_shared), ("burned_artifact_sha256s", burned)):
        if not isinstance(values, list):
            raise PopulationReadinessError(f"{label} must be a list")
        normalized = sorted(_sha(item, label=f"{label} item") for item in values)
        if values != normalized or len(values) != len(set(values)):
            raise PopulationReadinessError(f"{label} must be sorted and unique")
    if set(allowed_shared) & set(burned):
        raise PopulationReadinessError("allowed shared material cannot be burned")
    for field in ("required_population_size", "required_families", "required_per_family"):
        if isinstance(eligibility[field], bool) or not isinstance(eligibility[field], int):
            raise PopulationReadinessError(f"{field} must be an integer")
    if eligibility["required_families"] < 5:
        raise PopulationReadinessError("required_families must be at least five")
    if eligibility["required_per_family"] < 3:
        raise PopulationReadinessError("required_per_family must be at least three")
    if eligibility["required_population_size"] != eligibility["required_families"] * eligibility["required_per_family"]:
        raise PopulationReadinessError("required_population_size must equal families times per-family roots")
    for field in (
        "require_zero_parents",
        "require_unique_origin_session",
        "require_archive_source_identity",
    ):
        if eligibility[field] is not True:
            raise PopulationReadinessError(f"{field} must be true")
    threshold = eligibility["maximum_policy_shingle_jaccard"]
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise PopulationReadinessError("maximum_policy_shingle_jaccard must be numeric")
    if not 0.0 <= float(threshold) <= 0.90:
        raise PopulationReadinessError("maximum_policy_shingle_jaccard must be in [0, 0.90]")
    namespaces = eligibility["forbidden_context_namespaces"]
    if not isinstance(namespaces, list) or not namespaces:
        raise PopulationReadinessError("forbidden_context_namespaces must be a non-empty list")
    if namespaces != sorted(set(_identifier(item, label="forbidden namespace") for item in namespaces)):
        raise PopulationReadinessError("forbidden_context_namespaces must be sorted and unique")
    if eligibility["state"] != "FROZEN":
        raise PopulationReadinessError("eligibility state must be FROZEN")
    return eligibility


def build_context_manifest(content: Mapping[str, Any]) -> dict[str, Any]:
    if "content_sha256" in content:
        raise PopulationReadinessError("context manifest builder accepts hash-free content")
    return validate_context_manifest(_sealed(content))


def validate_context_manifest(value: object) -> dict[str, Any]:
    manifest = _validate_sealed(
        value,
        content_fields=_CONTEXT_CONTENT_FIELDS,
        fields=_CONTEXT_FIELDS,
        label="context manifest",
    )
    if manifest["schema"] != CONTEXT_MANIFEST_SCHEMA:
        raise PopulationReadinessError("context manifest schema mismatch")
    _uuid(manifest["origin_session_uuid"], label="origin_session_uuid")
    if not isinstance(manifest["entries"], list) or not manifest["entries"]:
        raise PopulationReadinessError("context manifest entries must be non-empty")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(manifest["entries"]):
        entry = _exact(raw, _CONTEXT_ENTRY_FIELDS, label=f"context entry {index}")
        path = _identifier(entry["path"], label=f"context entry {index}.path")
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or path != pure.as_posix():
            raise PopulationReadinessError("context paths must be canonical relative POSIX paths")
        role = _identifier(entry["role"], label=f"context entry {index}.role")
        if role not in _CONTEXT_ROLES:
            raise PopulationReadinessError("context entry role is not allowed")
        if path in seen:
            raise PopulationReadinessError("context manifest paths must be unique")
        seen.add(path)
        normalized.append({"path": path, "sha256": _sha(entry["sha256"], label="context sha256"), "role": role})
    normalized.sort(key=lambda row: row["path"])
    if manifest["entries"] != normalized:
        raise PopulationReadinessError("context entries must be canonical and sorted")
    if manifest["state"] != "SEALED":
        raise PopulationReadinessError("context manifest state must be SEALED")
    return manifest


def build_root_receipt(content: Mapping[str, Any]) -> dict[str, Any]:
    if "content_sha256" in content:
        raise PopulationReadinessError("root receipt builder accepts hash-free content")
    return validate_root_receipt(_sealed(content))


def validate_root_receipt(value: object) -> dict[str, Any]:
    receipt = _validate_sealed(
        value,
        content_fields=_RECEIPT_CONTENT_FIELDS,
        fields=_RECEIPT_FIELDS,
        label="root receipt",
    )
    if receipt["schema"] != ROOT_RECEIPT_SCHEMA:
        raise PopulationReadinessError("root receipt schema mismatch")
    _uuid(receipt["lineage_uuid"], label="lineage_uuid")
    _uuid(receipt["origin_session_uuid"], label="origin_session_uuid")
    if receipt["generation_mode"] not in _ALLOWED_GENERATION_MODES:
        raise PopulationReadinessError("root receipt generation_mode mismatch")
    for field in ("model_provider", "model_id", "model_request_id"):
        _identifier(receipt[field], label=field)
    for field in (
        "orchestrator_sha256",
        "packager_sha256",
        "uuid_allocation_sha256",
        "context_manifest_sha256",
        "source_tree_sha256",
        "archive_sha256",
        "compute_receipt_sha256",
    ):
        _sha(receipt[field], label=field)
    for field in ("input_artifact_sha256s", "human_patch_sha256s"):
        values = receipt[field]
        if not isinstance(values, list):
            raise PopulationReadinessError(f"{field} must be a list")
        normalized = sorted(_sha(item, label=f"{field} item") for item in values)
        if values != normalized or len(values) != len(set(values)):
            raise PopulationReadinessError(f"{field} must be sorted and unique")
    if receipt["parent_archive_sha256s"] != []:
        raise PopulationReadinessError("population roots must have zero parent archives")
    refs = receipt["prior_hosted_submission_refs"]
    if not isinstance(refs, list) or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in refs):
        raise PopulationReadinessError("prior_hosted_submission_refs must contain positive integers")
    if refs != sorted(set(refs)):
        raise PopulationReadinessError("prior_hosted_submission_refs must be sorted and unique")
    if receipt["outcome_conditioned"] is not False:
        raise PopulationReadinessError("root receipt must be outcome-free")
    if receipt["predictor_output_seen"] is not False:
        raise PopulationReadinessError("root builder must be blind to predictor output")
    if receipt["eligibility_result_seen"] is not False:
        raise PopulationReadinessError("root builder must be blind to eligibility results")
    started = _utc(receipt["started_at_utc"], label="started_at_utc")
    finished = _utc(receipt["finished_at_utc"], label="finished_at_utc")
    if finished < started:
        raise PopulationReadinessError("root receipt finished_at_utc predates start")
    if receipt["state"] != "SEALED":
        raise PopulationReadinessError("root receipt state must be SEALED")
    return receipt


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PopulationReadinessError(f"cannot read JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PopulationReadinessError(f"JSON artifact must be an object: {path}")
    return value


def _resolve(base_dir: Path, value: object, *, label: str) -> Path:
    path = Path(_identifier(value, label=label))
    return path if path.is_absolute() else (base_dir / path).resolve()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_tree_sha256(source_dir: str | Path) -> str:
    """Hash the candidate source tree with deterministic path/content framing."""

    root = Path(source_dir).resolve()
    if not root.is_dir():
        raise PopulationReadinessError(f"source directory does not exist: {root}")
    digest = hashlib.sha256()
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or any(part.startswith("._") for part in relative.parts):
            continue
        if path.suffix.lower() in {".pyc", ".pyo"} or path.name == ".DS_Store":
            continue
        files.append(path)
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _policy_shingles(source_dir: Path, *, width: int = 5) -> frozenset[str]:
    tokens: list[str] = []
    python_files = [
        path
        for path in source_dir.rglob("*.py")
        if "cg" not in path.relative_to(source_dir).parts and "__pycache__" not in path.parts
    ]
    for path in sorted(python_files, key=lambda item: item.relative_to(source_dir).as_posix()):
        try:
            stream = tokenize.generate_tokens(io.StringIO(path.read_text(encoding="utf-8")).readline)
            for token in stream:
                if token.type in {
                    tokenize.ENCODING,
                    tokenize.ENDMARKER,
                    tokenize.INDENT,
                    tokenize.DEDENT,
                    tokenize.NEWLINE,
                    tokenize.NL,
                    tokenize.COMMENT,
                }:
                    continue
                if token.type == tokenize.NAME and not keyword.iskeyword(token.string):
                    tokens.append("NAME")
                elif token.type == tokenize.NUMBER:
                    tokens.append("NUMBER")
                elif token.type == tokenize.STRING:
                    tokens.append("STRING")
                else:
                    tokens.append(token.string)
        except (OSError, UnicodeDecodeError, tokenize.TokenError, IndentationError) as exc:
            raise PopulationReadinessError(f"cannot tokenize policy source {path}: {exc}") from exc
    if not tokens:
        raise PopulationReadinessError("policy source contains no Python tokens")
    if len(tokens) < width:
        return frozenset({hashlib.sha256("\x1f".join(tokens).encode("utf-8")).hexdigest()})
    return frozenset(
        hashlib.sha256("\x1f".join(tokens[index : index + width]).encode("utf-8")).hexdigest()
        for index in range(len(tokens) - width + 1)
    )


def _jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _context_files_match(
    manifest: Mapping[str, Any],
    manifest_path: Path,
    *,
    forbidden_namespaces: set[str],
) -> None:
    for entry in manifest["entries"]:
        pure = PurePosixPath(entry["path"])
        lowered = {part.lower() for part in pure.parts}
        if lowered & forbidden_namespaces:
            raise PopulationReadinessError(
                f"context path enters a forbidden namespace: {entry['path']}"
            )
        path = (manifest_path.parent / pure.as_posix()).resolve()
        if manifest_path.parent.resolve() not in path.parents:
            raise PopulationReadinessError("context path escapes manifest directory")
        if not path.is_file() or _file_sha256(path) != entry["sha256"]:
            raise PopulationReadinessError(f"context file identity mismatch: {entry['path']}")


def _family_for_deck(ontology: Mapping[str, Any], deck_sha256: str) -> str:
    matches = [
        family["family_id"]
        for family in ontology["families"]
        if deck_sha256 in family["deck_sha256s"]
    ]
    if len(matches) != 1:
        raise PopulationReadinessError(
            f"deck {deck_sha256} maps to {len(matches)} ontology families"
        )
    return matches[0]


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


def _dependency_components(
    candidates: list[dict[str, Any]],
    *,
    allowed_shared: set[str],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    parents = {candidate["lineage_uuid"]: candidate["lineage_uuid"] for candidate in candidates}

    def find(value: str) -> str:
        while parents[value] != value:
            parents[value] = parents[parents[value]]
            value = parents[value]
        return value

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    owners: dict[str, list[str]] = {}
    for candidate in candidates:
        for digest in candidate["dependency_artifact_sha256s"]:
            if digest not in allowed_shared:
                owners.setdefault(digest, []).append(candidate["lineage_uuid"])
    for lineage_uuids in owners.values():
        for lineage_uuid in lineage_uuids[1:]:
            union(lineage_uuids[0], lineage_uuid)
    component_by_uuid = {lineage_uuid: find(lineage_uuid) for lineage_uuid in parents}
    shared = {
        digest: sorted(lineage_uuids)
        for digest, lineage_uuids in sorted(owners.items())
        if len(lineage_uuids) > 1
    }
    return component_by_uuid, shared


def compile_population_readiness(
    *,
    candidate_grammar: object,
    eligibility: object,
    family_ontology: object,
    roster: object,
    roster_base_dir: str | Path,
) -> dict[str, Any]:
    """Compile an outcome-free report; never create a final population."""

    grammar = validate_candidate_grammar(candidate_grammar)
    ontology = validate_family_ontology(family_ontology)
    rules = validate_eligibility(eligibility)
    checks: list[dict[str, Any]] = []
    checks.append(_check("candidate_grammar", True, grammar["content_sha256"]))
    checks.append(_check("family_ontology", True, ontology["content_sha256"]))
    checks.append(_check("eligibility", True, rules["content_sha256"]))
    checks.append(
        _check(
            "eligibility_bindings",
            rules["candidate_grammar_sha256"] == grammar["content_sha256"]
            and rules["family_ontology_sha256"] == ontology["content_sha256"],
            "eligibility must bind the exact grammar and ontology",
        )
    )
    checks.append(
        _check(
            "ontology_cardinality",
            len(ontology["families"]) == rules["required_families"],
            f"ontology={len(ontology['families'])} required={rules['required_families']}",
        )
    )

    raw_roster = _exact(roster, _ROSTER_FIELDS, label="population roster")
    if raw_roster["schema"] != ROSTER_SCHEMA:
        raise PopulationReadinessError("population roster schema mismatch")
    _identifier(raw_roster["roster_id"], label="roster_id")
    compute_budget = _identifier(raw_roster["compute_budget_id"], label="compute_budget_id")
    if raw_roster["state"] != "DRAFT":
        raise PopulationReadinessError("population roster state must be DRAFT")
    binding_pass = (
        raw_roster["candidate_grammar_sha256"] == grammar["content_sha256"]
        and raw_roster["eligibility_sha256"] == rules["content_sha256"]
        and raw_roster["family_ontology_sha256"] == ontology["content_sha256"]
    )
    checks.append(_check("roster_bindings", binding_pass, "roster must bind all exact rule artifacts"))
    records = raw_roster["records"]
    if not isinstance(records, list):
        raise PopulationReadinessError("population roster records must be a list")
    checks.append(
        _check(
            "population_cardinality",
            len(records) == rules["required_population_size"],
            f"expected={rules['required_population_size']} observed={len(records)}",
        )
    )

    base_dir = Path(roster_base_dir).resolve()
    candidates: list[dict[str, Any]] = []
    shingles: dict[str, frozenset[str]] = {}
    for index, raw in enumerate(records):
        blockers: list[str] = []
        derived: dict[str, Any] = {"position": index}
        try:
            record = _exact(raw, _ROSTER_RECORD_FIELDS, label=f"roster record {index}")
            lineage_uuid = _uuid(record["lineage_uuid"], label=f"record {index}.lineage_uuid")
            archive_path = _resolve(base_dir, record["archive_path"], label="archive_path")
            source_dir = _resolve(base_dir, record["source_dir"], label="source_dir")
            context_path = _resolve(base_dir, record["context_manifest_path"], label="context_manifest_path")
            receipt_path = _resolve(base_dir, record["root_receipt_path"], label="root_receipt_path")
            identity = inspect_archive(archive_path)
            source_hash = source_tree_sha256(source_dir)
            with tempfile.TemporaryDirectory(prefix="voi-p5-readiness-") as temporary:
                rebuilt = Path(temporary) / "candidate.tar.gz"
                rebuilt_hash = build_archive(source_dir, rebuilt)
            if rebuilt_hash != identity["archive_sha256"]:
                blockers.append("archive bytes are not the deterministic build of source_dir")
            context = validate_context_manifest(_load_json(context_path))
            receipt = validate_root_receipt(_load_json(receipt_path))
            _context_files_match(
                context,
                context_path,
                forbidden_namespaces={item.lower() for item in rules["forbidden_context_namespaces"]},
            )
            if context["origin_session_uuid"] != receipt["origin_session_uuid"]:
                blockers.append("context and receipt origin sessions differ")
            if receipt["lineage_uuid"] != lineage_uuid:
                blockers.append("receipt lineage UUID differs from roster")
            if receipt["context_manifest_sha256"] != context["content_sha256"]:
                blockers.append("receipt does not bind the exact context manifest")
            if receipt["source_tree_sha256"] != source_hash:
                blockers.append("receipt source tree hash mismatch")
            if receipt["archive_sha256"] != identity["archive_sha256"]:
                blockers.append("receipt archive hash mismatch")
            if receipt["orchestrator_sha256"] != rules["trusted_orchestrator_sha256"]:
                blockers.append("receipt orchestrator is not the frozen trusted orchestrator")
            if receipt["packager_sha256"] != rules["trusted_packager_sha256"]:
                blockers.append("receipt packager is not the frozen trusted packager")
            if receipt["uuid_allocation_sha256"] != rules["uuid_allocation_sha256"]:
                blockers.append("receipt does not bind the frozen UUID allocation")
            if receipt["generation_mode"] not in grammar["allowed_generation_modes"]:
                blockers.append("receipt generation mode is absent from the grammar")
            dependency_hashes = sorted(
                set(receipt["input_artifact_sha256s"])
                | set(receipt["human_patch_sha256s"])
                | {entry["sha256"] for entry in context["entries"]}
            )
            burned_overlap = sorted(set(dependency_hashes) & set(rules["burned_artifact_sha256s"]))
            if burned_overlap:
                blockers.append("root provenance includes a burned artifact")
            if receipt["prior_hosted_submission_refs"]:
                blockers.append("root ancestry already has hosted public outcomes")
            family_id = _family_for_deck(ontology, identity["deck_sha256"])
            ancestry_id = ancestry_id_for_roots([identity["archive_sha256"]])
            derived.update(
                {
                    "lineage_uuid": lineage_uuid,
                    "origin_session_uuid": receipt["origin_session_uuid"],
                    "model_request_id": receipt["model_request_id"],
                    "archive_sha256": identity["archive_sha256"],
                    "policy_content_sha256": identity["policy_content_sha256"],
                    "deck_sha256": identity["deck_sha256"],
                    "source_tree_sha256": source_hash,
                    "context_manifest_sha256": context["content_sha256"],
                    "root_receipt_sha256": receipt["content_sha256"],
                    "compute_receipt_sha256": receipt["compute_receipt_sha256"],
                    "dependency_artifact_sha256s": dependency_hashes,
                    "lineage_id": lineage_id_for_archive(identity["archive_sha256"]),
                    "ancestry_id": ancestry_id,
                    "family_id": family_id,
                    "compute_budget_id": compute_budget,
                }
            )
            shingles[lineage_uuid] = _policy_shingles(source_dir)
        except (OSError, PopulationReadinessError, ValueError) as exc:
            blockers.append(str(exc))
        derived["eligible"] = not blockers
        derived["blockers"] = blockers
        candidates.append(derived)

    complete = [candidate for candidate in candidates if candidate["eligible"]]
    identity_fields = (
        "lineage_uuid",
        "origin_session_uuid",
        "model_request_id",
        "archive_sha256",
        "policy_content_sha256",
        "source_tree_sha256",
        "ancestry_id",
        "compute_receipt_sha256",
    )
    for field in identity_fields:
        values = [candidate[field] for candidate in complete]
        checks.append(
            _check(
                f"unique_{field}",
                len(values) == len(set(values)),
                f"eligible={len(values)} unique={len(set(values))}",
            )
        )
    checks.append(
        _check(
            "all_records_eligible",
            len(complete) == len(records) == rules["required_population_size"],
            f"eligible={len(complete)} total={len(records)}",
        )
    )

    family_counts = {family["family_id"]: 0 for family in ontology["families"]}
    for candidate in complete:
        family_counts[candidate["family_id"]] += 1
    checks.append(
        _check(
            "family_balance",
            len(family_counts) == rules["required_families"]
            and all(count == rules["required_per_family"] for count in family_counts.values()),
            json.dumps(family_counts, sort_keys=True),
        )
    )

    component_by_uuid, shared_dependencies = _dependency_components(
        complete,
        allowed_shared=set(rules["allowed_shared_material_sha256s"]),
    )
    for candidate in complete:
        candidate["dependency_component_id"] = component_by_uuid[candidate["lineage_uuid"]]
    effective_roots = len(set(component_by_uuid.values()))
    family_effective_roots: dict[str, int] = {}
    for family_id in family_counts:
        family_effective_roots[family_id] = len(
            {
                component_by_uuid[candidate["lineage_uuid"]]
                for candidate in complete
                if candidate["family_id"] == family_id
            }
        )
    checks.append(
        _check(
            "dependency_independence",
            effective_roots == rules["required_population_size"] and not shared_dependencies,
            f"effective_roots={effective_roots} required={rules['required_population_size']} shared_nonallowlisted={len(shared_dependencies)}",
        )
    )
    checks.append(
        _check(
            "family_effective_roots",
            all(count == rules["required_per_family"] for count in family_effective_roots.values()),
            json.dumps(family_effective_roots, sort_keys=True),
        )
    )

    similarities: list[dict[str, Any]] = []
    uuids = sorted(shingles)
    for left_index, left in enumerate(uuids):
        for right in uuids[left_index + 1 :]:
            score = _jaccard(shingles[left], shingles[right])
            similarities.append({"left": left, "right": right, "jaccard": score})
    maximum = max((row["jaccard"] for row in similarities), default=0.0)
    checks.append(
        _check(
            "policy_near_clone_guard",
            maximum <= float(rules["maximum_policy_shingle_jaccard"]),
            f"maximum={maximum:.6f} threshold={float(rules['maximum_policy_shingle_jaccard']):.6f}",
        )
    )

    ready = all(check["passed"] for check in checks)
    content = {
        "schema": READINESS_SCHEMA,
        "roster_id": raw_roster["roster_id"],
        "candidate_grammar_sha256": grammar["content_sha256"],
        "eligibility_sha256": rules["content_sha256"],
        "family_ontology_sha256": ontology["content_sha256"],
        "checks": checks,
        "candidates": candidates,
        "family_counts": family_counts,
        "effective_ancestry_roots": effective_roots,
        "family_effective_roots": family_effective_roots,
        "shared_nonallowlisted_dependencies": shared_dependencies,
        "pairwise_policy_similarity": similarities,
        "decision": "READY_FOR_POPULATION_FREEZE" if ready else "CLOSED",
        "population_manifest_created": False,
        "kaggle_quota_authorized": False,
        "production_submission_authorized": False,
        "sealed_holdout_accessed": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def write_readiness_once(path: str | Path, report: Mapping[str, Any]) -> Path:
    if report.get("schema") != READINESS_SCHEMA:
        raise PopulationReadinessError("readiness report schema mismatch")
    expected = {key: value for key, value in report.items() if key != "content_sha256"}
    if report.get("content_sha256") != canonical_sha256(expected):
        raise PopulationReadinessError("readiness report content_sha256 mismatch")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as handle:
            handle.write(canonical_json_bytes(report) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"readiness report already exists: {target}") from None
    return target


__all__ = [
    "CANDIDATE_GRAMMAR_SCHEMA",
    "CONTEXT_MANIFEST_SCHEMA",
    "ELIGIBILITY_SCHEMA",
    "FAMILY_ONTOLOGY_SCHEMA",
    "READINESS_SCHEMA",
    "ROOT_RECEIPT_SCHEMA",
    "ROSTER_SCHEMA",
    "PopulationReadinessError",
    "build_candidate_grammar",
    "build_context_manifest",
    "build_eligibility",
    "build_family_ontology",
    "build_root_receipt",
    "compile_population_readiness",
    "source_tree_sha256",
    "validate_candidate_grammar",
    "validate_context_manifest",
    "validate_eligibility",
    "validate_family_ontology",
    "validate_root_receipt",
    "write_readiness_once",
]
