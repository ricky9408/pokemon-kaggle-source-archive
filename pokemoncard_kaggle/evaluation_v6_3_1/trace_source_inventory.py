"""Bounded lexical candidate inventory for the opened v6.3.1 engine.

This module is deliberately a source inventory, not a compiler scan.  It
records an over-approximation of source sites that a later independent AST/IR
review must classify and instrument.  Lexical evidence can never establish
trace completeness, build provenance, authority, upload permission, holdout
access, or permission to modify an agent.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping

from .common import canonical_sha256, zero_authority
from .engine_patch import PINNED_OPENED_SOURCE_TREE_SHA256, tree_sha256


TRACE_SOURCE_INVENTORY_SCHEMA = "eval.v6.3.1.trace-source-inventory.v1"
TRACE_SOURCE_INVENTORY_MODE = "TEST_ONLY/OFFLINE_LEXICAL_SOURCE_INVENTORY"
LEXICAL_INSUFFICIENT = "LEXICAL_SOURCE_INVENTORY_INSUFFICIENT_FOR_TRACE_COMPLETENESS"

FAMILY_SEMANTIC = "SEMANTIC_FIELD_DIRECT_WRITE"
FAMILY_CARD_ZONE = "CARD_ZONE_MOVE"
FAMILY_HP_DAMAGE = "HP_DAMAGE_WRITE"
FAMILY_RESULT = "RESULT_TERMINAL_WRITE"
FAMILY_RNG = "RNG_RANDOM_DEVICE_SHUFFLE"
FAMILY_SELECTION = "SELECTION_STACK_OPTIONS_CHECKS"
FAMILY_API = "API_IPC_ENTRYPOINT"
FAMILY_BOUNDARY = "STATE_STEP_CALL_FUNCTION_BOUNDARY"
FAMILY_RAW_MEMORY = "RAW_MEMORY_SERIALIZATION_HAZARD"

INVENTORY_FAMILIES = (
    FAMILY_SEMANTIC,
    FAMILY_CARD_ZONE,
    FAMILY_HP_DAMAGE,
    FAMILY_RESULT,
    FAMILY_RNG,
    FAMILY_SELECTION,
    FAMILY_API,
    FAMILY_BOUNDARY,
    FAMILY_RAW_MEMORY,
)

_SOURCE_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".c", ".cc", ".cpp", ".cxx"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FIELD_ACCESS = re.compile(r"\b[A-Za-z_]\w*(?:\s*(?:\.|->)\s*[A-Za-z_]\w*)+")
_ASSIGNMENT = re.compile(r"(?<![=!<>])(?:=|[+\-*/%&|^]=)(?![=])|\+\+|--")
_STRUCT_START = re.compile(r"\b(?:struct|class)\s+(State|Card|PlayerState|Game|EffectState)\b")
_FIELD_DECL = re.compile(
    r"^\s*(?:const\s+|static\s+|mutable\s+|unsigned\s+|signed\s+|short\s+|long\s+|"
    r"bool\s+|char\s+|int\s+|float\s+|double\s+|[A-Za-z_]\w*(?:::\w+|<[^;{}()]+>)?\s+)"
    r"[A-Za-z_]\w*(?:\s*\[[^]]*\])?\s*;\s*$"
)


class TraceSourceInventoryError(ValueError):
    """A candidate source inventory failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> TraceSourceInventoryError:
    return TraceSourceInventoryError(code, message)


def _authority() -> dict[str, Any]:
    return {
        "authority": False,
        "upload_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "holdout_access_authorized": False,
        "sealed_holdout_access_authorized": False,
        "campaign_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
    }


def _check_root(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail("TRACE_SOURCE_INVENTORY_ROOT_INVALID", f"{label} must be lowercase SHA-256 hex")
    return value


def _mask_cpp(text: str) -> str:
    """Mask comments and literals while preserving byte/line positions."""

    result = list(text)
    index = 0
    state = "code"
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                result[index] = result[index + 1] = " "
                index += 2
                state = "line-comment"
                continue
            if char == "/" and next_char == "*":
                result[index] = result[index + 1] = " "
                index += 2
                state = "block-comment"
                continue
            if char in {'"', "'"}:
                result[index] = " "
                state = "string" if char == '"' else "char"
            index += 1
            continue
        if state == "line-comment":
            if char == "\n":
                state = "code"
            elif char != "\r":
                result[index] = " "
            index += 1
            continue
        if state == "block-comment":
            if char == "*" and next_char == "/":
                result[index] = result[index + 1] = " "
                index += 2
                state = "code"
            else:
                if char not in {"\n", "\r"}:
                    result[index] = " "
                index += 1
            continue
        if char == "\\":
            result[index] = " "
            if index + 1 < len(text) and text[index + 1] not in {"\n", "\r"}:
                result[index + 1] = " "
                index += 2
            else:
                index += 1
        elif (state == "string" and char == '"') or (state == "char" and char == "'"):
            result[index] = " "
            state = "code"
            index += 1
        else:
            if char not in {"\n", "\r"}:
                result[index] = " "
            index += 1
    return "".join(result)


def _source_region(lines: list[str], masked_lines: list[str], index: int) -> bytes:
    """Return source bytes from the enclosing declaration through the site.

    The prefix distinguishes repeated identical statements in one function
    without using a line number or a path in the identity.
    """

    context = "translation-unit"
    start = 0
    for cursor in range(index, max(-1, index - 2000), -1):
        candidate = masked_lines[cursor].strip()
        if "{" in candidate and "(" in candidate and "=" not in candidate and not candidate.startswith(("if", "for", "while", "switch")):
            context = lines[cursor].strip()
            start = cursor
            break
        declaration = _STRUCT_START.search(candidate)
        if declaration:
            context = lines[cursor].strip()
            start = cursor
            break
    region_lines = [context, *lines[start + 1 : index + 1]] if start else lines[: index + 1]
    return ("\n".join(region_lines).replace("\r", "")).encode("utf-8")


@dataclass(frozen=True, slots=True)
class SourceCandidateSite:
    source_root_sha256: str
    canonical_relative_path: str
    family: str
    operation: str
    stable_site_id: str
    source_region_sha256: str
    source_region_text: str
    ast_ir_review_required: bool = True

    def canonical(self) -> dict[str, Any]:
        return {
            "source_root_sha256": self.source_root_sha256,
            "canonical_relative_path": self.canonical_relative_path,
            "family": self.family,
            "operation": self.operation,
            "stable_site_id": self.stable_site_id,
            "source_region_sha256": self.source_region_sha256,
            "source_region_text": self.source_region_text,
            "ast_ir_review_required": self.ast_ir_review_required,
        }


@dataclass(frozen=True, slots=True)
class TraceSourceInventory:
    source_root_sha256: str
    sites: tuple[SourceCandidateSite, ...]
    inventory_root_sha256: str
    schema: str = TRACE_SOURCE_INVENTORY_SCHEMA
    mode: str = TRACE_SOURCE_INVENTORY_MODE

    def canonical(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "mode": self.mode,
            "source_root_sha256": self.source_root_sha256,
            "sites": [site.canonical() for site in self.sites],
            "inventory_root_sha256": self.inventory_root_sha256,
            "lexical_source_inventory_sufficient": False,
            "trace_completeness_claimed": False,
            "trace_coverage_positive_buildable": False,
            "authority": _authority(),
        }

    def zero_authority_report(self) -> dict[str, Any]:
        return zero_authority(
            "OFFLINE_LEXICAL_SOURCE_INVENTORY",
            detail=LEXICAL_INSUFFICIENT,
            extra={
                "authority": False,
                "upload_authorized": False,
                "inventory_root_sha256": self.inventory_root_sha256,
                "source_root_sha256": self.source_root_sha256,
                "lexical_source_inventory_sufficient": False,
                "trace_completeness_claimed": False,
                "trace_coverage_positive_buildable": False,
                "holdout_access_authorized": False,
                "campaign_authorized": False,
            },
        )

    def to_trace_coverage(self, *_args: Any, **_kwargs: Any) -> None:
        raise _fail("TRACE_SOURCE_INVENTORY_NOT_TRACE_COVERAGE", LEXICAL_INSUFFICIENT)


def _site_id(canonical_relative_path: str, family: str, region: bytes) -> tuple[str, str]:
    region_sha = hashlib.sha256(region).hexdigest()
    stable = hashlib.sha256(
        b"V631/SOURCE-SITE\0"
        + canonical_relative_path.encode("utf-8")
        + b"\0"
        + family.encode("ascii")
        + b"\0"
        + region
    ).hexdigest()
    return stable, region_sha


def _iter_source_files(root: Path) -> tuple[Path, ...]:
    if not root.is_dir():
        raise _fail("TRACE_SOURCE_INVENTORY_SOURCE_MISSING", "opened source root is missing")
    return tuple(sorted((path for path in root.rglob("*") if path.is_file() and path.suffix in _SOURCE_SUFFIXES), key=lambda item: item.relative_to(root).as_posix()))


def _struct_field_indices(masked_lines: list[str]) -> set[int]:
    indices: set[int] = set()
    active: list[tuple[str, int]] = []
    depth = 0
    for index, line in enumerate(masked_lines):
        for match in _STRUCT_START.finditer(line):
            active.append((match.group(1), depth + line[: match.start()].count("{") - line[: match.start()].count("}")))
        if active and _FIELD_DECL.match(line) and "(" not in line:
            indices.add(index)
        depth += line.count("{") - line.count("}")
        active = [(name, start) for name, start in active if depth >= start]
    return indices


def _operations(masked: str, field_index: bool) -> tuple[tuple[str, str], ...]:
    operations: list[tuple[str, str]] = []
    if field_index:
        operations.append((FAMILY_SEMANTIC, "semantic_field_declaration"))
    assignment = _ASSIGNMENT.search(masked)
    field_write = assignment is not None and _FIELD_ACCESS.search(masked[: assignment.start()]) is not None
    if field_write:
        operations.append((FAMILY_SEMANTIC, "semantic_direct_write_or_counter"))
    if re.search(r"\b(?:MoveList[A-Za-z_]*|MoveCard|removeCardRef|pushCardRef|cardMoved|LogMoveCard)\s*\(", masked):
        operations.append((FAMILY_CARD_ZONE, "card_zone_move_or_gateway"))
    if re.search(r"(?:\.\s*|->\s*)(?:hp|damage|hpChange|damageChange[A-Za-z_]*)\b", masked) or re.search(r"\b(?:AddDamage|Heal|CalcDamage|ClampShort)\s*\(", masked):
        operations.append((FAMILY_HP_DAMAGE, "hp_or_damage_mutation"))
    if re.search(r"\b(?:setResult|gameResult|finishReason|isFinish|finishCheck|apiResult|LogResult)\s*[=(]|\b(?:setResult|isFinish|finishCheck|LogResult)\s*\(", masked):
        operations.append((FAMILY_RESULT, "result_or_terminal_transition"))
    if re.search(r"\b(?:random_device|getrandom|random_shuffle)\b|\bshuffle\s*\(|\b(?:rng|seed)\b", masked):
        operations.append((FAMILY_RNG, "rng_entropy_or_permutation"))
    if re.search(r"\b(?:setSelect|clearSelect|setSelectMinMaxAny|addOption|selectedOption|selectedYes|checkPlayerSelect)\s*\(|\b(?:options|selected|functionStack|delayTriggerStack|temporaryTriggerStack|triggerStack)\s*\.\s*(?:clear|push_back|pop_back|erase|emplace_back)\s*\(", masked):
        operations.append((FAMILY_SELECTION, "selection_stack_option_or_legality"))
    if re.search(r"\b(?:GAME_API|BattleStart|AgentStart|BattleFinish|GetBattleData|Select|VisualizeData|SearchBegin|SearchStep|SearchEnd|SearchRelease|Api[A-Z]|SetBattleData)\b", masked):
        operations.append((FAMILY_API, "api_or_ipc_entrypoint"))
    if re.search(r"\b(?:step|callFunction)\s*\(|\b(?:state\.)?(?:step|callFunction)\s*\(", masked):
        operations.append((FAMILY_BOUNDARY, "state_step_or_call_function_boundary"))
    if re.search(r"\b(?:memset|memcpy|memmove|serialize|deserialize)\s*\(|\b(?:BinaryWriter|BinaryReader)\b|\bb\.set\s*\(&turn\s*,\s*&options\)|\b(?:state|State)\s*=", masked):
        operations.append((FAMILY_RAW_MEMORY, "raw_memory_or_state_serialization_hazard"))
    return tuple(operations)


def _scan_sites(root: Path, source_root: str) -> tuple[SourceCandidateSite, ...]:
    sites: list[SourceCandidateSite] = []
    seen: set[tuple[str, str]] = set()
    for path in _iter_source_files(root):
        text = path.read_text(encoding="utf-8-sig")
        masked = _mask_cpp(text)
        lines = text.splitlines()
        masked_lines = masked.splitlines()
        if len(lines) != len(masked_lines):
            raise _fail("TRACE_SOURCE_INVENTORY_LEXER_INVALID", f"line masking changed line count for {path}")
        field_indices = _struct_field_indices(masked_lines)
        relative = path.relative_to(root).as_posix()
        for index, (line, masked_line) in enumerate(zip(lines, masked_lines, strict=True)):
            for family, operation in _operations(masked_line, index in field_indices):
                region = _source_region(lines, masked_lines, index)
                stable_id, region_sha = _site_id(relative, family, region)
                key = (family, stable_id)
                if key in seen:
                    raise _fail("TRACE_SOURCE_INVENTORY_DUPLICATE_SITE", f"duplicate {family} source region in {relative}")
                seen.add(key)
                sites.append(SourceCandidateSite(source_root, relative, family, operation, stable_id, region_sha, line.strip()))
    sites.sort(key=lambda item: (item.canonical_relative_path, item.family, item.source_region_sha256, item.operation, item.stable_site_id))
    return tuple(sites)


def _inventory_root(source_root: str, sites: tuple[SourceCandidateSite, ...]) -> str:
    return canonical_sha256({
        "schema": TRACE_SOURCE_INVENTORY_SCHEMA,
        "mode": TRACE_SOURCE_INVENTORY_MODE,
        "source_root_sha256": source_root,
        "sites": [site.canonical() for site in sites],
        "lexical_source_inventory_sufficient": False,
        "trace_completeness_claimed": False,
        "trace_coverage_positive_buildable": False,
        "authority": _authority(),
    })


def build_trace_source_inventory(source_root: Path) -> TraceSourceInventory:
    """Scan only the pinned opened source tree and return a zero-authority candidate inventory."""

    actual_root = tree_sha256(source_root)
    if actual_root != PINNED_OPENED_SOURCE_TREE_SHA256:
        raise _fail("TRACE_SOURCE_INVENTORY_SOURCE_ROOT_DRIFT", "opened source root is not the pinned df523358... tree")
    sites = _scan_sites(source_root, actual_root)
    present = {site.family for site in sites}
    missing = sorted(set(INVENTORY_FAMILIES) - present)
    if missing:
        raise _fail("TRACE_SOURCE_INVENTORY_UNCLASSIFIED_SITE", f"candidate inventory has empty families: {missing}")
    return TraceSourceInventory(actual_root, sites, _inventory_root(actual_root, sites))


def validate_trace_source_inventory(value: TraceSourceInventory | Mapping[str, Any], source_root: Path) -> TraceSourceInventory:
    """Re-scan source and reject omissions, additions, duplicate rows, or claims."""

    if isinstance(value, TraceSourceInventory):
        wire = value.canonical()
    elif type(value) is dict:
        wire = value
    else:
        raise _fail("TRACE_SOURCE_INVENTORY_INVALID", "inventory must be a TraceSourceInventory or exact mapping")
    expected_fields = {
        "schema", "mode", "source_root_sha256", "sites", "inventory_root_sha256",
        "lexical_source_inventory_sufficient", "trace_completeness_claimed",
        "trace_coverage_positive_buildable", "authority",
    }
    if set(wire) != expected_fields or wire["schema"] != TRACE_SOURCE_INVENTORY_SCHEMA or wire["mode"] != TRACE_SOURCE_INVENTORY_MODE:
        raise _fail("TRACE_SOURCE_INVENTORY_INVALID", "inventory fields or schema are not exact")
    if wire["lexical_source_inventory_sufficient"] is not False or wire["trace_completeness_claimed"] is not False or wire["trace_coverage_positive_buildable"] is not False:
        raise _fail("TRACE_SOURCE_INVENTORY_AUTHORITY_CLAIM", "lexical inventory cannot claim trace completeness")
    if wire["authority"] != _authority():
        raise _fail("TRACE_SOURCE_INVENTORY_AUTHORITY_CLAIM", "inventory authority fields must remain false")
    seen_ids: set[str] = set()
    sites = wire["sites"]
    if type(sites) is not list or not sites:
        raise _fail("TRACE_SOURCE_INVENTORY_UNCLASSIFIED_SITE", "inventory sites must be a nonempty list")
    for index, site in enumerate(sites):
        if type(site) is not dict or set(site) != set(SourceCandidateSite("", "", "", "", "", "", "").canonical()):
            raise _fail("TRACE_SOURCE_INVENTORY_UNCLASSIFIED_SITE", f"site {index} fields are not exact")
        scalar_fields = (
            "source_root_sha256", "canonical_relative_path", "family", "operation",
            "stable_site_id", "source_region_sha256", "source_region_text",
        )
        if any(type(site[field]) is not str for field in scalar_fields):
            raise _fail("TRACE_SOURCE_INVENTORY_UNCLASSIFIED_SITE", f"site {index} scalar fields must be strings")
        if (
            site["source_root_sha256"] != wire["source_root_sha256"]
            or _SHA256_RE.fullmatch(site["stable_site_id"]) is None
            or _SHA256_RE.fullmatch(site["source_region_sha256"]) is None
            or not site["canonical_relative_path"]
            or Path(site["canonical_relative_path"]).is_absolute()
            or ".." in Path(site["canonical_relative_path"]).parts
        ):
            raise _fail("TRACE_SOURCE_INVENTORY_UNCLASSIFIED_SITE", f"site {index} identity fields are invalid")
        if site["family"] not in INVENTORY_FAMILIES or not site["operation"] or site["ast_ir_review_required"] is not True:
            raise _fail("TRACE_SOURCE_INVENTORY_UNCLASSIFIED_SITE", f"site {index} is not classified for later AST/IR review")
        if site["stable_site_id"] in seen_ids:
            raise _fail("TRACE_SOURCE_INVENTORY_DUPLICATE_SITE", f"duplicate stable site ID {site['stable_site_id']}")
        seen_ids.add(site["stable_site_id"])
    actual_root = tree_sha256(source_root)
    if actual_root != PINNED_OPENED_SOURCE_TREE_SHA256 or wire["source_root_sha256"] != actual_root:
        raise _fail("TRACE_SOURCE_INVENTORY_SOURCE_ROOT_DRIFT", "inventory is not bound to the pinned opened source root")
    expected = build_trace_source_inventory(source_root)
    if wire["inventory_root_sha256"] != expected.inventory_root_sha256 or wire["sites"] != [site.canonical() for site in expected.sites]:
        raise _fail("TRACE_SOURCE_INVENTORY_UNCOVERED_SITE", "inventory differs from the deterministic source rescan")
    return expected


__all__ = [
    "FAMILY_API", "FAMILY_BOUNDARY", "FAMILY_CARD_ZONE", "FAMILY_HP_DAMAGE",
    "FAMILY_RAW_MEMORY", "FAMILY_RESULT", "FAMILY_RNG", "FAMILY_SELECTION",
    "FAMILY_SEMANTIC", "INVENTORY_FAMILIES", "LEXICAL_INSUFFICIENT",
    "PINNED_OPENED_SOURCE_TREE_SHA256", "SourceCandidateSite", "TraceSourceInventory",
    "TraceSourceInventoryError", "TRACE_SOURCE_INVENTORY_MODE", "TRACE_SOURCE_INVENTORY_SCHEMA",
    "build_trace_source_inventory", "validate_trace_source_inventory",
]
