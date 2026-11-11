"""Fail-closed static closure analysis for real entropy collector output.

This analyzer is intentionally read-only.  It consumes the report emitted by
``entropy_real_collection`` plus the collector's artifact directory, verifies
the byte bindings, and parses the raw AST, LLVM IR, and binary-inspection
output itself.  Its only successful state is a *local* static closure; it can
never create a permit or authorize a campaign action.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

from .common import canonical_sha256
from .entropy_real_collection import PROBE_MODE, PROBE_STATE, REAL_ENTROPY_PROBE_SCHEMA, tree_sha256


STATIC_CLOSURE_SCHEMA = "eval.v6.3.1.entropy-static-closure.v1"
STATIC_CLOSURE_MODE = "OFFLINE_STATIC_ANALYSIS/NO_UPLOAD"
FROZEN_ENTROPY_ALLOWLIST = (
    "V631DeterministicRngGateway::raw_draw",
    "V631DeterministicRngGateway::bounded",
    "V631DeterministicRngGateway::shuffle",
    "V631DeterministicRngGateway::seed_from_descriptor",
)
FROZEN_ENTROPY_ALLOWLIST_SHA256 = canonical_sha256(
    {"schema": "eval.v6.3.1.entropy-static-allowlist.v1", "symbols": list(FROZEN_ENTROPY_ALLOWLIST)}
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RELATIVE_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*(?:/[A-Za-z0-9][A-Za-z0-9._+-]*)*$")
_LLVM_DIRECT_CALL_RE = re.compile(r"\b(?:call|invoke)\b[^@%\n]*@(?P<target>[A-Za-z$._][A-Za-z0-9$._-]*)\s*\(")
_LLVM_INDIRECT_CALL_RE = re.compile(
    r"\b(?:call|invoke)\b[^\n]*%(?P<target>[A-Za-z0-9$._-]+)\s*\("
)
_LLVM_DEFINE_RE = re.compile(
    r'^\s*define\b.*?@(?:"(?P<quoted>[^"]+)"|(?P<plain>[A-Za-z$._][A-Za-z0-9$._-]*))\s*\('
)
_FORBIDDEN_SUBSTRINGS = (
    "arc4random",
    "getentropy",
    "getrandom",
    "random_device",
    "random_shuffle",
    "mt19937",
    "rdrand",
    "rdseed",
    "clock_gettime",
    "gettimeofday",
    "steady_clock",
    "system_clock",
    "pthread_create",
    "dlopen",
    "urandom",
    "/dev/random",
    "/dev/urandom",
    "entropy",
)
_FORBIDDEN_EXACT_SYMBOLS = frozenset(
    {
        "rand",
        "rand_r",
        "random",
        "random_r",
        "srand",
        "srandom",
        "syscall",
        "time",
    }
)
_HARDWARE_OR_SYSCALL_INSTRUCTION_RE = re.compile(
    r"\b(?:rdrand|rdseed|syscall|sysenter)\b",
    re.IGNORECASE,
)
_AST_GATEWAY_METHODS = frozenset(
    {"raw_draw", "bounded", "shuffle", "seed_from_descriptor"}
)
_AST_FUNCTION_DECL_KINDS = frozenset(
    {
        "FunctionDecl",
        "CXXMethodDecl",
        "CXXConstructorDecl",
        "CXXConversionDecl",
    }
)
_AST_RECORD_DECL_KINDS = frozenset(
    {
        "CXXRecordDecl",
        "ClassTemplateSpecializationDecl",
    }
)
_DISPATCH_SIGNATURES = (
    "GameFunctionNoArg",
    "GameFunctionI",
    "GameFunctionB",
    "GameFunctionII",
    "GameFunctionIII",
)
_DISPATCH_SIGNATURE_SCAN_ORDER = (
    "GameFunctionNoArg",
    "GameFunctionIII",
    "GameFunctionII",
    "GameFunctionB",
    "GameFunctionI",
)
_DISPATCH_IR_FUNCTION = "_ZN5State12callFunctionEv"
_EXPECTED_REGISTRY_TARGET_COUNT = 116
_EXPECTED_REGISTRY_REFERENCES = MappingProxyType(
    {
        ("FunctionTable", "InitializeBattleFunction", "push_back"): 116,
        ("FunctionTable", "InitializeBattleFunction", "range"): 1,
        ("FunctionTable", "InitializeBattleFunction", "operator[]"): 1,
        ("FunctionIndexTable", "InitializeBattleFunction", "operator[]"): 1,
        ("FunctionIndexTable", "GameFunction::GameFunction", "at"): 1,
        ("FunctionTable", "State::callFunction", "at"): 1,
        ("FunctionTable", "InitializeAll", "size"): 1,
    }
)
_REQUIRED_INSPECTIONS = ("nm", "otool", "objdump")


class EntropyStaticClosureError(ValueError):
    """The requested analyzer inputs are not a safe static-analysis request."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> EntropyStaticClosureError:
    return EntropyStaticClosureError(code, message)


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _digest_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _safe_relative(value: Any, label: str) -> str:
    # The real collector's marker is the one frozen hidden path.  All other
    # hidden or traversal-shaped artifact names remain rejected.
    if (
        type(value) is not str
        or (value != ".entropy-real-collection.marker" and _RELATIVE_PATH_RE.fullmatch(value) is None)
        or value in {".", ".."}
    ):
        raise _fail("STATIC_PATH_INVALID", f"{label} must be a canonical relative POSIX path")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail("STATIC_DIGEST_INVALID", f"{label} must be a lowercase SHA-256 digest")
    return value


def _safe_directory(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise _fail("STATIC_PATH_INVALID", f"{label} must be an absolute, non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _fail("STATIC_PATH_INVALID", f"{label} cannot be resolved") from exc
    for item in path.rglob("*"):
        if item.is_symlink() or (not item.is_dir() and not item.is_file()):
            raise _fail("STATIC_SYMLINK_REJECTED", f"{label} contains an unsafe entry: {item}")
    return resolved


def _safe_report_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise _fail("STATIC_REPORT_PATH_INVALID", "collector_report_path must be an absolute, non-symlink regular file")
    return path.resolve(strict=True)


def _artifact_path(root: Path, relative: Any) -> Path:
    name = _safe_relative(relative, "artifact path")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise _fail("STATIC_ARTIFACT_PATH_INVALID", f"artifact is absent or unsafe: {name}")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise _fail("STATIC_ARTIFACT_ESCAPE", f"artifact escapes artifact_directory: {name}") from exc
    return resolved


def _decode_report(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("STATIC_REPORT_MALFORMED", "collector report must be a UTF-8 JSON object") from exc
    if type(value) is not dict:
        raise _fail("STATIC_REPORT_MALFORMED", "collector report must be a JSON object")
    if value.get("schema") != REAL_ENTROPY_PROBE_SCHEMA or value.get("mode") != PROBE_MODE or value.get("state") != PROBE_STATE:
        raise _fail("STATIC_REPORT_SCHEMA_INVALID", "collector report is not the frozen real-collector schema")
    declared = _sha(value.get("report_sha256"), "report_sha256")
    if declared != canonical_sha256({key: value[key] for key in value if key != "report_sha256"}):
        raise _fail("STATIC_REPORT_DIGEST_DRIFT", "collector report hash does not bind its contents")
    for key in ("source_tree_sha256", "derivative_tree_sha256", "linked_binary_sha256"):
        _sha(value.get(key), key)
    for key in ("translation_units", "ast", "llvm_ir", "generated_artifacts"):
        if type(value.get(key)) is not list:
            raise _fail("STATIC_REPORT_SCHEMA_INVALID", f"collector report {key} must be a list")
    if type(value.get("inspection")) is not dict or type(value.get("compiler")) is not dict:
        raise _fail("STATIC_REPORT_SCHEMA_INVALID", "collector report omits compiler or inspection records")
    return value


def _tool_binding(record: Mapping[str, Any], label: str) -> tuple[bool, str]:
    tool = record.get("tool", record)
    if type(tool) is not dict:
        return False, f"{label}_TOOL_RECORD_MALFORMED"
    requested = tool.get("resolved_path")
    expected = tool.get("sha256")
    if type(requested) is not str or not os.path.isabs(requested) or not _SHA256_RE.fullmatch(expected if type(expected) is str else ""):
        return False, f"{label}_TOOL_PIN_MISSING"
    path = Path(requested)
    try:
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK) or _digest_file(path) != expected:
            return False, f"{label}_TOOL_DIGEST_DRIFT"
    except OSError:
        return False, f"{label}_TOOL_UNAVAILABLE"
    return True, ""


def _forbidden_symbol(symbol: str, context: str = "") -> bool:
    lower = symbol.lower().lstrip("_")
    context_lower = context.lower()
    strong_context_tokens = (
        "arc4random",
        "getentropy",
        "getrandom",
        "random_device",
        "random_shuffle",
        "mt19937",
        "rdrand",
        "rdseed",
        "clock_gettime",
        "gettimeofday",
        "steady_clock",
        "system_clock",
        "pthread_create",
        "dlopen",
        "urandom",
        "/dev/random",
        "/dev/urandom",
    )
    return (
        lower in _FORBIDDEN_EXACT_SYMBOLS
        or any(token in lower for token in _FORBIDDEN_SUBSTRINGS)
        or any(token in context_lower for token in strong_context_tokens)
    )


def _gateway_symbol(symbol: str, context: str = "") -> bool:
    lower = symbol.lower()
    combined = f"{symbol} {context}"
    if "V631DeterministicRngGateway" in combined:
        return (
            any(method in lower for method in _AST_GATEWAY_METHODS)
            or any(
                marker in symbol
                for marker in ("8raw_draw", "7bounded", "7shuffle", "20seed_from_descriptor")
            )
        )
    return False


def _normalize_symbol(value: Any) -> str | None:
    if type(value) is not str:
        return None
    name = value.strip().lstrip("@_")
    return name if name else None


def _ast_callee_info(node: Mapping[str, Any]) -> tuple[str | None, str]:
    children = node.get("inner", [])
    if type(children) is not list or not children or type(children[0]) is not dict:
        return None, ""
    callee = children[0]
    targets: list[str] = []
    context: list[str] = []

    def walk(value: Any) -> None:
        if type(value) is not dict:
            return
        kind = value.get("kind")
        if type(kind) is str:
            context.append(kind)
        type_record = value.get("type")
        if type(type_record) is dict:
            for key in ("qualType", "desugaredQualType"):
                if type(type_record.get(key)) is str:
                    context.append(type_record[key])
        if kind == "MemberExpr":
            target = _normalize_symbol(value.get("name"))
            if target is not None:
                targets.append(target)
        elif kind in {
            "CXXDependentScopeMemberExpr",
            "DependentScopeDeclRefExpr",
            "UnresolvedLookupExpr",
            "UnresolvedMemberExpr",
        }:
            target = _normalize_symbol(value.get("member") or value.get("name"))
            if target is not None:
                targets.append(target)
        for key in ("referencedDecl", "decl", "callee"):
            candidate = value.get(key)
            if type(candidate) is dict and candidate.get("kind") in {
                "FunctionDecl",
                "CXXMethodDecl",
                "CXXConstructorDecl",
                "CXXConversionDecl",
                "FunctionTemplateDecl",
            }:
                target = _normalize_symbol(candidate.get("name"))
                if target is not None:
                    targets.append(target)
                mangled = _normalize_symbol(candidate.get("mangledName"))
                if mangled is not None:
                    context.append(mangled)
        for child in value.get("inner", []):
            walk(child)

    walk(callee)
    return (targets[0] if targets else None), " ".join(context)


def _ast_explicit_source_file(node: Mapping[str, Any]) -> str | None:
    locations: list[Mapping[str, Any]] = []
    if type(node.get("loc")) is dict:
        locations.append(node["loc"])
    range_record = node.get("range")
    if type(range_record) is dict:
        for key in ("begin", "end"):
            if type(range_record.get(key)) is dict:
                locations.append(range_record[key])
    def preferred_path(location: Any) -> str | None:
        if type(location) is not dict:
            return None
        # Macro expansions are semantically owned by their expansion site.
        # Spelling locations are consulted only when no expansion site exists.
        for key in ("expansionLoc", "presumedLoc"):
            candidate = preferred_path(location.get(key))
            if candidate is not None:
                return candidate
        if type(location.get("file")) is str:
            return location["file"]
        return preferred_path(location.get("spellingLoc"))

    for location in locations:
        path = preferred_path(location)
        if path is not None:
            return path
    return None


def _ast_source_is_owned(source_file: str, derivative_root: Path) -> bool:
    if (
        not source_file
        or "\x00" in source_file
        or (source_file.startswith("<") and source_file.endswith(">"))
    ):
        return False
    path = Path(source_file)
    candidate = (
        path.resolve(strict=False)
        if path.is_absolute()
        else (derivative_root / path).resolve(strict=False)
    )
    try:
        candidate.relative_to(derivative_root)
        return True
    except ValueError:
        return False


def _ast_location_is_owned(
    node: Mapping[str, Any],
    derivative_root: Path,
) -> bool:
    source_file = _ast_explicit_source_file(node)
    return source_file is None or _ast_source_is_owned(source_file, derivative_root)


def _ast_dispatch_signature(context: str) -> str | None:
    for signature in _DISPATCH_SIGNATURE_SCAN_ORDER:
        if signature in context:
            return signature
    return None


def _ast_referenced_declarations(
    node: Any,
    *,
    declaration_kinds: frozenset[str] | None = None,
    declaration_names: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    declarations: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if type(value) is not dict:
            return
        referenced = value.get("referencedDecl")
        if type(referenced) is dict:
            kind = referenced.get("kind")
            name = referenced.get("name")
            if (
                (declaration_kinds is None or kind in declaration_kinds)
                and (declaration_names is None or name in declaration_names)
            ):
                declarations.append(referenced)
        children = value.get("inner", [])
        if type(children) is list:
            for child in children:
                walk(child)

    walk(node)
    return declarations


def _ast_function_owner(
    node: Mapping[str, Any],
    record_stack: Sequence[str],
) -> str | None:
    name = node.get("name")
    if type(name) is not str or not name:
        return None
    return f"{record_stack[-1]}::{name}" if record_stack else name


def _new_ast_registry_evidence(unit: str) -> dict[str, Any]:
    return {
        "unit": unit,
        "table_declarations": [],
        "index_declarations": [],
        "references": [],
        "registry_entries": [],
        "owned_function_definitions": {},
    }


def _walk_ast(
    node: Any,
    unit: str,
    derivative_root: Path,
    inherited_source_file: str,
    ordinal: list[int],
    edges: list[dict[str, Any]],
    evidence: dict[str, Any],
    record_stack: list[str],
    function_stack: list[str],
    call_stack: list[str | None],
) -> None:
    if type(node) is not dict:
        return
    source_file = _ast_explicit_source_file(node) or inherited_source_file
    kind = node.get("kind")
    owned = _ast_source_is_owned(source_file, derivative_root)
    pushed_record = False
    pushed_function = False
    pushed_call = False

    if owned and kind in _AST_RECORD_DECL_KINDS:
        record_name = node.get("name")
        if type(record_name) is str and record_name:
            record_stack.append(record_name)
            pushed_record = True
    if owned and kind in _AST_FUNCTION_DECL_KINDS:
        owner = _ast_function_owner(node, record_stack)
        if owner is not None:
            function_stack.append(owner)
            pushed_function = True
        declaration_id = node.get("id")
        children = node.get("inner", [])
        has_body = type(children) is list and any(
            type(child) is dict and child.get("kind") == "CompoundStmt"
            for child in children
        )
        if (
            has_body
            and type(declaration_id) is str
            and type(node.get("name")) is str
        ):
            type_record = node.get("type")
            evidence["owned_function_definitions"][declaration_id] = {
                "name": node["name"],
                "qual_type": (
                    type_record.get("qualType", "")
                    if type(type_record) is dict
                    else ""
                ),
            }
    if owned and kind == "VarDecl" and node.get("name") in {
        "FunctionTable",
        "FunctionIndexTable",
    }:
        type_record = node.get("type")
        declaration = {
            "id": node.get("id"),
            "name": node.get("name"),
            "qual_type": (
                type_record.get("qualType", "")
                if type(type_record) is dict
                else ""
            ),
        }
        key = (
            "table_declarations"
            if node.get("name") == "FunctionTable"
            else "index_declarations"
        )
        evidence[key].append(declaration)

    target: str | None = None
    context = ""
    if (
        owned
        and type(kind) is str
        and (kind == "CallExpr" or kind.endswith("CallExpr"))
    ):
        target, context = _ast_callee_info(node)
        call_stack.append(target)
        pushed_call = True
        if (
            function_stack
            and function_stack[-1] == "InitializeBattleFunction"
            and target == "push_back"
        ):
            children = node.get("inner", [])
            object_references = (
                _ast_referenced_declarations(
                    children[0],
                    declaration_kinds=frozenset({"VarDecl"}),
                    declaration_names=frozenset({"FunctionTable"}),
                )
                if type(children) is list
                and children
                and type(children[0]) is dict
                else []
            )
            target_references: list[dict[str, Any]] = []
            if type(children) is list:
                for child in children[1:]:
                    target_references.extend(
                        _ast_referenced_declarations(
                            child,
                            declaration_kinds=frozenset({"FunctionDecl"}),
                        )
                    )
            if len(object_references) == 1 and len(target_references) == 1:
                referenced = target_references[0]
                type_record = referenced.get("type")
                evidence["registry_entries"].append(
                    {
                        "decl_id": referenced.get("id"),
                        "name": referenced.get("name"),
                        "qual_type": (
                            type_record.get("qualType", "")
                            if type(type_record) is dict
                            else ""
                        ),
                    }
                )

    if owned and kind == "DeclRefExpr":
        referenced = node.get("referencedDecl")
        if (
            type(referenced) is dict
            and referenced.get("kind") == "VarDecl"
            and referenced.get("name") in {"FunctionTable", "FunctionIndexTable"}
        ):
            evidence["references"].append(
                {
                    "decl_id": referenced.get("id"),
                    "table": referenced.get("name"),
                    "owner": function_stack[-1] if function_stack else "<global>",
                    "operation": call_stack[-1] if call_stack else None,
                }
            )

    if (
        owned
        and type(kind) is str
        and (kind == "CallExpr" or kind.endswith("CallExpr"))
    ):
        ordinal[0] += 1
        if target is None:
            template_dependent = any(
                marker in context
                for marker in (
                    "Dependent",
                    "Unresolved",
                    "<dependent type>",
                    "<overloaded function type>",
                )
            )
            edges.append(
                {
                    "origin": "AST",
                    "unit": unit,
                    "ordinal": ordinal[0],
                    "kind": (
                        "TEMPLATE_DEPENDENT"
                        if template_dependent
                        else "INDIRECT"
                    ),
                    "target": None,
                    "resolved": template_dependent,
                    "owner": function_stack[-1] if function_stack else None,
                    "dispatch_signature": _ast_dispatch_signature(context),
                }
            )
        elif _gateway_symbol(target, context):
            edges.append(
                {
                    "origin": "AST",
                    "unit": unit,
                    "ordinal": ordinal[0],
                    "kind": "GATEWAY",
                    "target": target,
                    "resolved": True,
                }
            )
        elif _forbidden_symbol(target, context):
            edges.append(
                {
                    "origin": "AST",
                    "unit": unit,
                    "ordinal": ordinal[0],
                    "kind": "FORBIDDEN",
                    "target": target,
                    "resolved": False,
                }
            )
    children = node.get("inner", [])
    if type(children) is list:
        for child in children:
            _walk_ast(
                child,
                unit,
                derivative_root,
                source_file,
                ordinal,
                edges,
                evidence,
                record_stack,
                function_stack,
                call_stack,
            )
    if pushed_call:
        call_stack.pop()
    if pushed_function:
        function_stack.pop()
    if pushed_record:
        record_stack.pop()


def _parse_ast(
    path: Path,
    unit: str,
    derivative_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        root = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("STATIC_AST_MALFORMED", f"AST is not valid JSON: {path.name}") from exc
    if type(root) is not dict or root.get("kind") != "TranslationUnitDecl":
        raise _fail("STATIC_AST_MALFORMED", f"AST has no TranslationUnitDecl root: {path.name}")
    edges: list[dict[str, Any]] = []
    evidence = _new_ast_registry_evidence(unit)
    _walk_ast(
        root,
        unit,
        derivative_root,
        str(derivative_root / unit),
        [0],
        edges,
        evidence,
        [],
        [],
        [],
    )
    return edges, evidence


def _llvm_call_arguments(line: str, open_paren_index: int) -> list[str] | None:
    depth = 1
    argument_start = open_paren_index + 1
    argument_text: str | None = None
    for index in range(argument_start, len(line)):
        character = line[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                argument_text = line[argument_start:index]
                break
    if argument_text is None:
        return None
    if not argument_text.strip():
        return []
    arguments: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(argument_text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            arguments.append(argument_text[start:index].strip())
            start = index + 1
    arguments.append(argument_text[start:].strip())
    return arguments


def _llvm_dispatch_signature(line: str, indirect: re.Match[str]) -> str | None:
    arguments = _llvm_call_arguments(line, indirect.end() - 1)
    if arguments is None:
        return None
    argument_types = [
        argument.split(maxsplit=1)[0]
        for argument in arguments
        if argument
    ]
    signatures = {
        ("ptr",): "GameFunctionNoArg",
        ("ptr", "i32"): "GameFunctionI",
        ("ptr", "i1"): "GameFunctionB",
        ("ptr", "i32", "i32"): "GameFunctionII",
        ("ptr", "i32", "i32", "i32"): "GameFunctionIII",
    }
    return signatures.get(tuple(argument_types))


def _parse_ir(path: Path, unit: str) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise _fail("STATIC_IR_MALFORMED", f"LLVM IR is not UTF-8 text: {path.name}") from exc
    edges: list[dict[str, Any]] = []
    current_function: str | None = None
    for line_number, line in enumerate(lines, start=1):
        definition = _LLVM_DEFINE_RE.search(line)
        if definition is not None:
            current_function = definition.group("quoted") or definition.group("plain")
        if not re.search(r"\b(?:call|invoke)\b", line):
            if line.strip() == "}":
                current_function = None
            continue
        direct = _LLVM_DIRECT_CALL_RE.search(line)
        indirect = _LLVM_INDIRECT_CALL_RE.search(line)
        if direct is not None:
            target = _normalize_symbol(direct.group("target"))
            if target is not None and _gateway_symbol(target):
                edges.append({"origin": "LLVM_IR", "unit": unit, "ordinal": line_number, "kind": "GATEWAY", "target": target, "resolved": True})
            elif target is not None and _forbidden_symbol(target):
                edges.append({"origin": "LLVM_IR", "unit": unit, "ordinal": line_number, "kind": "FORBIDDEN", "target": target, "resolved": False})
        elif indirect is not None:
            edges.append(
                {
                    "origin": "LLVM_IR",
                    "unit": unit,
                    "ordinal": line_number,
                    "kind": "INDIRECT",
                    "target": _normalize_symbol(indirect.group("target")),
                    "resolved": False,
                    "owner": current_function,
                    "dispatch_signature": _llvm_dispatch_signature(line, indirect),
                }
            )
        elif " asm " in f" {line} ":
            edges.append({"origin": "LLVM_IR", "unit": unit, "ordinal": line_number, "kind": "INLINE_ASM", "target": None, "resolved": False})
        else:
            edges.append({"origin": "LLVM_IR", "unit": unit, "ordinal": line_number, "kind": "UNRESOLVED", "target": None, "resolved": False})
        if line.strip() == "}":
            current_function = None
    return edges


def _dispatch_registry_proof(
    ast_evidence: Sequence[Mapping[str, Any]],
    ast_edges: list[dict[str, Any]],
    ir_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    table_declarations: list[Mapping[str, Any]] = []
    index_declarations: list[Mapping[str, Any]] = []
    references: list[Mapping[str, Any]] = []
    registry_entries: list[Mapping[str, Any]] = []
    definitions: dict[str, Mapping[str, Any]] = {}
    for evidence in ast_evidence:
        table_declarations.extend(evidence["table_declarations"])
        index_declarations.extend(evidence["index_declarations"])
        references.extend(evidence["references"])
        registry_entries.extend(evidence["registry_entries"])
        for declaration_id, definition in evidence[
            "owned_function_definitions"
        ].items():
            if declaration_id in definitions and definitions[declaration_id] != definition:
                definitions[declaration_id] = {
                    "name": "<duplicate>",
                    "qual_type": "",
                }
            else:
                definitions[declaration_id] = definition

    ast_dispatch = [
        edge
        for edge in ast_edges
        if edge["kind"] == "INDIRECT"
        and edge.get("owner") == "State::callFunction"
        and edge.get("dispatch_signature") in _DISPATCH_SIGNATURES
    ]
    ir_dispatch = [
        edge
        for edge in ir_edges
        if edge["kind"] == "INDIRECT"
        and edge.get("owner") == _DISPATCH_IR_FUNCTION
        and edge.get("dispatch_signature") in _DISPATCH_SIGNATURES
    ]
    present = bool(
        table_declarations
        or index_declarations
        or references
        or registry_entries
        or ast_dispatch
        or ir_dispatch
    )
    failures: list[str] = []
    reference_counts: Counter[tuple[Any, Any, Any]] = Counter()
    ast_signature_counts: Counter[Any] = Counter()
    ir_signature_counts: Counter[Any] = Counter()
    if present:
        if len(table_declarations) != 1:
            failures.append("REGISTRY_FUNCTION_TABLE_DECLARATION_INVALID")
        if len(index_declarations) != 1:
            failures.append("REGISTRY_FUNCTION_INDEX_DECLARATION_INVALID")
        table_id = (
            table_declarations[0].get("id")
            if len(table_declarations) == 1
            else None
        )
        index_id = (
            index_declarations[0].get("id")
            if len(index_declarations) == 1
            else None
        )
        if (
            len(table_declarations) == 1
            and (
                type(table_id) is not str
                or table_declarations[0].get("qual_type") != "std::vector<void *>"
            )
        ):
            failures.append("REGISTRY_FUNCTION_TABLE_DECLARATION_INVALID")
        if (
            len(index_declarations) == 1
            and (
                type(index_id) is not str
                or index_declarations[0].get("qual_type")
                != "std::unordered_map<long long, int>"
            )
        ):
            failures.append("REGISTRY_FUNCTION_INDEX_DECLARATION_INVALID")

        reference_counts = Counter(
            (
                reference.get("table"),
                reference.get("owner"),
                reference.get("operation"),
            )
            for reference in references
        )
        expected_reference_counts = Counter(_EXPECTED_REGISTRY_REFERENCES)
        if reference_counts != expected_reference_counts:
            failures.append("REGISTRY_REFERENCE_CLOSURE_INVALID")
        if any(
            reference.get("decl_id")
            != (
                table_id
                if reference.get("table") == "FunctionTable"
                else index_id
            )
            for reference in references
        ):
            failures.append("REGISTRY_REFERENCE_DECLARATION_MISMATCH")

        if len(registry_entries) != _EXPECTED_REGISTRY_TARGET_COUNT:
            failures.append("REGISTRY_TARGET_COUNT_INVALID")
        target_names = [entry.get("name") for entry in registry_entries]
        target_ids = [entry.get("decl_id") for entry in registry_entries]
        if (
            any(type(name) is not str or not name for name in target_names)
            or len(set(target_names)) != len(target_names)
            or any(type(target_id) is not str for target_id in target_ids)
            or len(set(target_ids)) != len(target_ids)
        ):
            failures.append("REGISTRY_TARGET_IDENTITY_INVALID")
        for entry in registry_entries:
            definition = definitions.get(entry.get("decl_id"))
            if (
                definition is None
                or definition.get("name") != entry.get("name")
                or definition.get("qual_type") != entry.get("qual_type")
            ):
                failures.append("REGISTRY_TARGET_DEFINITION_MISSING")
                break

        ast_signature_counts = Counter(
            edge.get("dispatch_signature") for edge in ast_dispatch
        )
        ir_signature_counts = Counter(
            edge.get("dispatch_signature") for edge in ir_dispatch
        )
        expected_signatures = Counter(
            {signature: 1 for signature in _DISPATCH_SIGNATURES}
        )
        if ast_signature_counts != expected_signatures:
            failures.append("REGISTRY_AST_DISPATCH_INVALID")
        if ir_signature_counts != expected_signatures:
            failures.append("REGISTRY_IR_DISPATCH_INVALID")
        ir_targets = {edge.get("target") for edge in ir_dispatch}
        if len(ir_targets) != 1 or None in ir_targets:
            failures.append("REGISTRY_IR_TARGET_IDENTITY_INVALID")

    complete = present and not failures
    if complete:
        for edge in ast_dispatch + ir_dispatch:
            edge["kind"] = "REGISTERED_GAME_DISPATCH"
            edge["resolved"] = True

    public_entries = [
        {
            "index": index,
            "name": entry["name"],
            "qual_type": entry["qual_type"],
        }
        for index, entry in enumerate(registry_entries)
        if type(entry.get("name")) is str
        and type(entry.get("qual_type")) is str
    ]
    target_root = (
        canonical_sha256(
            {
                "schema": "eval.v6.3.1.compiler-derived-function-registry.v1",
                "entries": public_entries,
            }
        )
        if len(public_entries) == len(registry_entries) and registry_entries
        else None
    )
    return {
        "schema": "eval.v6.3.1.compiler-derived-dispatch-proof.v1",
        "present": present,
        "complete": complete,
        "target_count": len(registry_entries),
        "target_root_sha256": target_root,
        "targets": public_entries,
        "reference_counts": [
            {
                "table": key[0],
                "owner": key[1],
                "operation": key[2],
                "count": count,
            }
            for key, count in sorted(
                reference_counts.items(),
                key=lambda item: tuple(str(part) for part in item[0]),
            )
        ],
        "expected_reference_counts": [
            {
                "table": key[0],
                "owner": key[1],
                "operation": key[2],
                "count": count,
            }
            for key, count in sorted(
                _EXPECTED_REGISTRY_REFERENCES.items(),
                key=lambda item: tuple(str(part) for part in item[0]),
            )
        ],
        "ast_dispatch_signatures": dict(sorted(ast_signature_counts.items())),
        "ir_dispatch_signatures": dict(sorted(ir_signature_counts.items())),
        "failure_codes": sorted(set(failures)),
    }


def _inspection_forbidden(kind: str, text: str) -> list[str]:
    hits: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if kind == "nm":
            symbol = stripped.split()[-1]
            if _forbidden_symbol(symbol):
                hits.add(f"{kind}:{stripped}")
        elif kind == "objdump":
            symbols = re.findall(r"<([^>]+)>", stripped)
            if any(_forbidden_symbol(symbol) for symbol in symbols) or _HARDWARE_OR_SYSCALL_INSTRUCTION_RE.search(stripped):
                hits.add(f"{kind}:{stripped}")
        elif kind == "otool":
            dependency = stripped.split(" (", 1)[0]
            if dependency.startswith(("/dev/random", "/dev/urandom")):
                hits.add(f"{kind}:{stripped}")
    return sorted(hits)


def _report_artifacts(report: Mapping[str, Any], root: Path) -> tuple[dict[str, Path], list[str]]:
    artifacts: dict[str, Path] = {}
    failures: list[str] = []
    for row in report["generated_artifacts"]:
        if type(row) is not dict or set(row) != {"path", "sha256", "bytes"}:
            failures.append("ARTIFACT_MANIFEST_MALFORMED")
            continue
        try:
            relative = _safe_relative(row["path"], "generated artifact path")
            expected = _sha(row["sha256"], f"generated artifact {relative}")
            if type(row["bytes"]) is not str or not row["bytes"].isdigit():
                raise _fail("STATIC_ARTIFACT_MANIFEST_INVALID", "artifact byte count is invalid")
            if relative in artifacts:
                failures.append("ARTIFACT_MANIFEST_DUPLICATE")
                continue
            path = _artifact_path(root, relative)
            if _digest_file(path) != expected or path.stat().st_size != int(row["bytes"]):
                failures.append("ARTIFACT_DIGEST_DRIFT")
            artifacts[relative] = path
        except EntropyStaticClosureError as exc:
            failures.append(exc.code)
    actual = {item.relative_to(root).as_posix() for item in root.rglob("*") if item.is_file()}
    if set(artifacts) != actual:
        failures.append("ARTIFACT_DIRECTORY_INVENTORY_MISMATCH")
    return artifacts, failures


def _command_artifact(record: Mapping[str, Any], artifacts: Mapping[str, Path], label: str) -> str | None:
    command = record.get("command", record)
    if type(command) is not dict or type(command.get("stdout")) is not dict:
        return None
    stdout = command["stdout"]
    path = stdout.get("path")
    digest = stdout.get("sha256")
    if type(path) is not str or type(digest) is not str or path not in artifacts:
        return None
    return path if _digest_file(artifacts[path]) == digest else None


def _zero_authority(status: str, report_hash: str, details: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "schema": STATIC_CLOSURE_SCHEMA,
        "mode": STATIC_CLOSURE_MODE,
        "status": status,
        "state": "NO_UPLOAD",
        "collector_report_sha256": report_hash,
        "frozen_allowlist_sha256": FROZEN_ENTROPY_ALLOWLIST_SHA256,
        "details": dict(details),
        "authority": False,
        "upload_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "holdout_access_authorized": False,
        "sealed_holdout_access_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
    }
    payload["report_sha256"] = canonical_sha256(payload)
    return payload


@dataclass(frozen=True, slots=True)
class EntropyStaticClosureReport:
    """Immutable static result.  ``COMPLETE`` remains offline and NO_UPLOAD."""

    _wire: Mapping[str, Any]

    @property
    def status(self) -> str:
        return self._wire["status"]

    def canonical(self) -> dict[str, Any]:
        return _thaw(self._wire)

    def zero_authority_report(self) -> dict[str, Any]:
        return self.canonical()


def analyze_entropy_static_closure(
    *,
    collector_report_path: str | Path,
    artifact_directory: str | Path,
    source_directory: str | Path | None = None,
    derivative_directory: str | Path | None = None,
    frozen_allowlist_sha256: str | None = FROZEN_ENTROPY_ALLOWLIST_SHA256,
) -> EntropyStaticClosureReport:
    """Analyze immutable real collector bytes without executing them.

    Missing optional root directories prevent ``COMPLETE`` rather than being
    silently trusted.  The function never writes to either input path.
    """

    root = _safe_directory(artifact_directory, "artifact_directory")
    report_path = _safe_report_path(collector_report_path)
    report_file_digest = _digest_file(report_path)
    root_before = tree_sha256(root)
    report = _decode_report(report_path)
    failures: list[str] = []
    if frozen_allowlist_sha256 != FROZEN_ENTROPY_ALLOWLIST_SHA256:
        failures.append("FROZEN_ALLOWLIST_MISMATCH")

    artifacts, manifest_failures = _report_artifacts(report, root)
    failures.extend(manifest_failures)
    bindings: dict[str, Any] = {
        "source_tree_sha256": report["source_tree_sha256"],
        "derivative_tree_sha256": report["derivative_tree_sha256"],
        "linked_binary_sha256": report["linked_binary_sha256"],
        "artifact_tree_sha256": root_before,
        "report_file_sha256": report_file_digest,
    }
    verified_derivative_root: Path | None = None
    for label, supplied, expected in (
        ("SOURCE", source_directory, report["source_tree_sha256"]),
        ("DERIVATIVE", derivative_directory, report["derivative_tree_sha256"]),
    ):
        if supplied is None:
            failures.append(f"{label}_ROOT_UNAVAILABLE")
        else:
            try:
                checked_directory = _safe_directory(
                    supplied,
                    f"{label.lower()}_directory",
                )
                actual = tree_sha256(checked_directory)
                bindings[f"{label.lower()}_actual_tree_sha256"] = actual
                if actual != expected:
                    failures.append(f"{label}_ROOT_DIGEST_DRIFT")
                elif label == "DERIVATIVE":
                    verified_derivative_root = checked_directory
            except EntropyStaticClosureError as exc:
                failures.append(exc.code)

    compiler_ok, compiler_failure = _tool_binding(report["compiler"], "COMPILER")
    if not compiler_ok:
        failures.append(compiler_failure)
    inspection_text: dict[str, str] = {}
    for name in _REQUIRED_INSPECTIONS:
        record = report["inspection"].get(name)
        if type(record) is not dict:
            failures.append(f"INSPECTION_{name.upper()}_MISSING")
            continue
        tool_ok, tool_failure = _tool_binding(record, f"INSPECTION_{name.upper()}")
        if not tool_ok:
            failures.append(tool_failure)
        output_path = _command_artifact(record, artifacts, name)
        if output_path is None:
            failures.append(f"INSPECTION_{name.upper()}_OUTPUT_UNBOUND")
            continue
        try:
            inspection_text[name] = artifacts[output_path].read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append(f"INSPECTION_{name.upper()}_OUTPUT_MALFORMED")

    ast_edges: list[dict[str, Any]] = []
    ir_edges: list[dict[str, Any]] = []
    ast_registry_evidence: list[dict[str, Any]] = []
    expected_units = report["translation_units"]
    if not expected_units or any(type(unit) is not str for unit in expected_units) or expected_units != sorted(set(expected_units)):
        failures.append("TRANSLATION_UNIT_INVENTORY_INVALID")
    for category, digest_key, suffix, parser, bucket in (
        (report["ast"], "ast_sha256", ".json", _parse_ast, ast_edges),
        (report["llvm_ir"], "ir_sha256", ".ll", _parse_ir, ir_edges),
    ):
        records = category
        units: list[str] = []
        consumed_paths: set[str] = set()
        for index, record in enumerate(records):
            if type(record) is not dict or type(record.get("translation_unit")) is not str or not _SHA256_RE.fullmatch(record.get(digest_key, "")):
                failures.append("COMPILER_OUTPUT_RECORD_MALFORMED")
                continue
            unit = record["translation_unit"]
            units.append(unit)
            path = _command_artifact(record, artifacts, unit)
            # IR is an output file, while AST is command stdout.
            if suffix == ".ll":
                # The collector fixes the IR name by its canonical TU ordinal.
                # A digest match at an arbitrary path is not a source binding.
                candidate = f"ir/tu-{index:04d}.ll"
                path = candidate if candidate in artifacts else None
            if path is None or _digest_file(artifacts[path]) != record[digest_key]:
                failures.append("COMPILER_OUTPUT_DIGEST_DRIFT")
                continue
            consumed_paths.add(path)
            try:
                if parser is _parse_ast:
                    if verified_derivative_root is None:
                        failures.append("DERIVATIVE_ROOT_UNAVAILABLE_FOR_AST")
                        continue
                    parsed_edges, parsed_evidence = parser(
                        artifacts[path],
                        unit,
                        verified_derivative_root,
                    )
                    bucket.extend(parsed_edges)
                    ast_registry_evidence.append(parsed_evidence)
                else:
                    bucket.extend(parser(artifacts[path], unit))
            except EntropyStaticClosureError as exc:
                failures.append(exc.code)
        expected_raw_paths = {
            name for name in artifacts
            if name.startswith("ast/") and name.endswith(".json")
        } if suffix == ".json" else {
            name for name in artifacts
            if name.startswith("ir/") and name.endswith(".ll")
        }
        if units != expected_units or len(units) != len(set(units)) or consumed_paths != expected_raw_paths:
            failures.append("COMPILER_OUTPUT_INVENTORY_INCOMPLETE")

    binary = artifacts.get("binary/derivative-probe")
    if binary is None or _digest_file(binary) != report["linked_binary_sha256"]:
        failures.append("LINKED_BINARY_DIGEST_DRIFT")
    forbidden_binary: list[str] = []
    for name, output in inspection_text.items():
        forbidden_binary.extend(_inspection_forbidden(name, output))
    forbidden_binary.sort()
    if forbidden_binary:
        failures.append("FORBIDDEN_BINARY_ENTROPY_SIGNAL")

    dispatch_proof = _dispatch_registry_proof(
        ast_registry_evidence,
        ast_edges,
        ir_edges,
    )
    failures.extend(dispatch_proof["failure_codes"])
    edges = sorted(ast_edges + ir_edges, key=lambda item: (item["origin"], item["unit"], item["ordinal"], item["kind"], item["target"] or ""))
    unresolved = [edge for edge in edges if not edge["resolved"]]
    if unresolved:
        failures.append("UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL")

    root_after = tree_sha256(root)
    if root_after != root_before or _digest_file(report_path) != report_file_digest:
        failures.append("INPUT_MUTATED_DURING_ANALYSIS")
    details = {
        "bindings": bindings,
        "required_inspections": list(_REQUIRED_INSPECTIONS),
        "entropy_call_edges": edges,
        "unresolved_or_disallowed_call_edges": unresolved,
        "compiler_derived_dispatch_proof": dispatch_proof,
        "forbidden_binary_signals": forbidden_binary,
        "failure_codes": sorted(set(failures)),
        "static_closure_complete": not failures,
    }
    wire = _zero_authority("COMPLETE" if not failures else "INCOMPLETE", report["report_sha256"], details)
    return EntropyStaticClosureReport(_freeze(wire))


analyze_static_entropy_closure = analyze_entropy_static_closure


__all__ = [
    "EntropyStaticClosureError",
    "EntropyStaticClosureReport",
    "FROZEN_ENTROPY_ALLOWLIST",
    "FROZEN_ENTROPY_ALLOWLIST_SHA256",
    "STATIC_CLOSURE_MODE",
    "STATIC_CLOSURE_SCHEMA",
    "analyze_entropy_static_closure",
    "analyze_static_entropy_closure",
]
