#!/usr/bin/env python3
"""Independent zero-authority verifier for the v631302 worker bytecode policy."""

from __future__ import annotations

import ast
from collections import Counter
from hashlib import sha256
import json
import opcode
from pathlib import Path
import sys
from types import CodeType


ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "worker/v631302_diagnostic_worker_v1.py"
PROJECT_PATHS = (
    "evaluation_v6_3_1/__init__.py",
    "evaluation_v6_3_1/m0_diagnostic_census.py",
    "evaluation_v6_3_1/m0_diagnostic_primitives.py",
)
INTERPRETER_SIZE = 6_834_488
INTERPRETER_SHA256 = "6d972cf21be56fe3c947ab6ba257ff8d08c342dd2714442986791bd9a6dfabfe"
OPCODE_ORACLE_PATH = Path("/usr/lib/python3.11/opcode.py")
OPCODE_ORACLE_SIZE = 10_447
OPCODE_ORACLE_SHA256 = "e6fc6dc49ced415d6ec285aaf1076148b8c4cb253d3a4d2384a7bab994d394bf"
BASE_OPCODE_MAP_ROOT = "3b1cc4c4171c908b2880c20838f4eebf80de54fbe10b46e7d5c74f6e23d0fb77"
INLINE_CACHE_WIDTHS_ROOT = "6216aa659e01666076e2a4d62983aa5993062a502d57cf5bb8303005f081ae32"

EXPLICITLY_PROHIBITED_NAMES = frozenset(
    (
        "IMPORT_STAR",
        "LOAD_BUILD_CLASS",
        "STORE_ATTR",
        "DELETE_ATTR",
        "CALL_FUNCTION_EX",
        "RETURN_GENERATOR",
        "YIELD_VALUE",
        "GET_YIELD_FROM_ITER",
        "GET_AITER",
        "GET_ANEXT",
        "BEFORE_ASYNC_WITH",
        "END_ASYNC_FOR",
        "WITH_EXCEPT_START",
        "BEFORE_WITH",
        "MATCH_CLASS",
        "MATCH_MAPPING",
        "MATCH_SEQUENCE",
        "MATCH_KEYS",
        "LOAD_ASSERTION_ERROR",
        "FORMAT_VALUE",
        "BUILD_STRING",
        "PRINT_EXPR",
    )
)
EXPECTED_FORBIDDEN_NAMES = frozenset(
    (
        "__self__",
        "__globals__",
        "__subclasses__",
        "__getattribute__",
        "__dict__",
        "__builtins__",
        "__import__",
        "globals",
        "locals",
        "vars",
        "dir",
        "getattr",
        "setattr",
        "delattr",
        "hasattr",
        "eval",
        "exec",
        "compile",
        "open",
        "input",
        "breakpoint",
        "help",
    )
)
EXPECTED_PERMITTED_ATTRIBUTES = frozenset(
    (
        "add",
        "annotations",
        "append",
        "bit_length",
        "clear",
        "copy",
        "count",
        "decode",
        "discard",
        "encode",
        "endswith",
        "extend",
        "find",
        "from_bytes",
        "fromhex",
        "get",
        "hex",
        "index",
        "insert",
        "isascii",
        "items",
        "join",
        "keys",
        "pop",
        "remove",
        "replace",
        "reverse",
        "setdefault",
        "sort",
        "split",
        "splitlines",
        "startswith",
        "strip",
        "to_bytes",
        "update",
        "values",
    )
)


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 0xFF:
        return bytes(((major << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")


def _cbor(value: object) -> bytes:
    if type(value) is int:
        if value < 0:
            raise ValueError("negative integer")
        return _head(0, value)
    if type(value) is bytes:
        return _head(2, len(value)) + value
    if type(value) is str:
        raw = value.encode("utf-8", "strict")
        return _head(3, len(raw)) + raw
    if type(value) is list:
        return _head(4, len(value)) + b"".join(_cbor(item) for item in value)
    raise TypeError(type(value))


def _root(domain: bytes, payload: list[object]) -> str:
    return sha256(_cbor([domain, 631302, 1, payload])).hexdigest()


def _bytes(path: Path) -> tuple[bytes, str]:
    raw = path.read_bytes()
    return raw, sha256(raw).hexdigest()


def _assignment(tree: ast.Module, name: str) -> object:
    matches = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ]
    if len(matches) != 1:
        raise ValueError(f"missing unique assignment: {name}")
    value = matches[0]
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "frozenset"
        and len(value.args) == 1
        and not value.keywords
    ):
        value = value.args[0]
    return ast.literal_eval(value)


def _walk(code: CodeType, path: tuple[int, ...] = ()) -> list[tuple[tuple[int, ...], CodeType]]:
    rows = [(path, code)]
    for index, value in enumerate(code.co_consts):
        if type(value) is CodeType:
            rows.extend(_walk(value, path + (index,)))
    return rows


def _instruction_rows(
    raw: bytes,
    *,
    defined: set[int],
    cache_widths: list[int],
) -> list[list[int]]:
    """Parse pinned 3.11 wordcode without using the worker or ``dis``."""
    if not raw or len(raw) % 2:
        raise ValueError("invalid compiled wordcode length")
    rows: list[list[int]] = []
    offset = 0
    while offset < len(raw):
        start = offset
        extended = 0
        extended_count = 0
        while offset < len(raw) and raw[offset] == 144:
            if offset + 1 >= len(raw) or extended_count >= 3:
                raise ValueError("invalid EXTENDED_ARG chain")
            extended = (extended << 8) | raw[offset + 1]
            extended_count += 1
            offset += 2
        if offset + 1 >= len(raw):
            raise ValueError("truncated compiled wordcode")
        operation = raw[offset]
        if operation in (0, 144) or operation not in defined:
            raise ValueError("undefined or parser-control executable opcode")
        if extended_count and operation < 90:
            raise ValueError("EXTENDED_ARG before no-argument opcode")
        if operation < 90 and raw[offset + 1] != 0:
            raise ValueError("nonzero argument on no-argument opcode")
        argument = (extended << 8) | raw[offset + 1]
        rows.append([start, operation, argument])
        offset += 2
        for _ in range(cache_widths[operation]):
            if offset + 1 >= len(raw) or raw[offset:offset + 2] != b"\x00\x00":
                raise ValueError("invalid compiled inline-cache run")
            offset += 2
    return rows


def _runtime_identity() -> list[object]:
    executable = Path("/proc/self/exe")
    if not executable.is_file():
        raise ValueError("pinned CPython 3.11.2 identity mismatch")
    raw, digest = _bytes(executable)
    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:3] != (3, 11, 2)
        or sys.implementation.cache_tag != "cpython-311"
        or sys.abiflags != ""
        or len(raw) != INTERPRETER_SIZE
        or digest != INTERPRETER_SHA256
    ):
        raise ValueError("pinned CPython 3.11.2 identity mismatch")
    return [3, 11, 2, len(raw), bytes.fromhex(digest)]


def verify() -> dict[str, object]:
    interpreter_record = _runtime_identity()
    oracle_raw, oracle_digest = _bytes(OPCODE_ORACLE_PATH)
    if (
        Path(opcode.__file__).resolve() != OPCODE_ORACLE_PATH
        or len(oracle_raw) != OPCODE_ORACLE_SIZE
        or oracle_digest != OPCODE_ORACLE_SHA256
    ):
        raise ValueError("pinned opcode.py identity mismatch")

    base_rows: list[list[object]] = [[index, ""] for index in range(256)]
    for name, value in opcode.opmap.items():
        if type(name) is not str or type(value) is not int or not 0 <= value < 256:
            raise ValueError("invalid opcode oracle row")
        if base_rows[value][1] != "":
            raise ValueError("duplicate opcode oracle value")
        base_rows[value][1] = name
    cache_widths = list(opcode._inline_cache_entries)
    if len(cache_widths) != 256 or any(type(value) is not int or value < 0 for value in cache_widths):
        raise ValueError("invalid inline-cache oracle")
    base_root = sha256(
        _cbor([b"V631302_CPYTHON311_BASE_OPCODE_MAP_V1", 631302, 1, 3, 11, 2, base_rows])
    ).hexdigest()
    cache_root = sha256(
        _cbor([b"V631302_CPYTHON311_CACHE_WIDTHS_V1", 631302, 1, 3, 11, 2, cache_widths])
    ).hexdigest()
    if base_root != BASE_OPCODE_MAP_ROOT or cache_root != INLINE_CACHE_WIDTHS_ROOT:
        raise ValueError("normative CPython table root mismatch")

    worker_raw, worker_digest = _bytes(WORKER_PATH)
    worker_tree = ast.parse(worker_raw, filename=str(WORKER_PATH))
    permitted = sorted(_assignment(worker_tree, "_PERMITTED_OPCODES"))
    cache_nonzero = _assignment(worker_tree, "_INLINE_CACHE_ENTRIES")
    name_opcodes = set(_assignment(worker_tree, "_NAME_OPCODES"))
    attribute_opcodes = set(_assignment(worker_tree, "_ATTRIBUTE_OPCODES"))
    worker_name_rules = _assignment(worker_tree, "_CO_NAMES_INDEX_RULES")
    write_name_opcodes = set(_assignment(worker_tree, "_WRITE_NAME_OPCODES"))
    forbidden_names = set(_assignment(worker_tree, "_FORBIDDEN_NAMES"))
    permitted_attributes = set(_assignment(worker_tree, "_PERMITTED_ATTRIBUTES"))
    forward_jumps = set(_assignment(worker_tree, "_FORWARD_JUMPS"))
    backward_jumps = set(_assignment(worker_tree, "_BACKWARD_JUMPS"))
    fast_opcodes = set(_assignment(worker_tree, "_FAST_OPCODES"))
    localsplus_opcodes = set(_assignment(worker_tree, "_LOCALSPLUS_OPCODES"))
    if any(type(value) is not int for value in permitted):
        raise ValueError("worker permitted-opcode table is not integral")
    if type(cache_nonzero) is not dict or any(
        type(key) is not int or type(value) is not int for key, value in cache_nonzero.items()
    ):
        raise ValueError("worker cache table is invalid")
    expected_nonzero = {index: width for index, width in enumerate(cache_widths) if width}
    if cache_nonzero != expected_nonzero:
        raise ValueError("worker cache table differs from pinned CPython")

    defined = {index for index, name in base_rows if name}
    parser_control = {0, 144}
    if permitted != sorted(set(permitted)) or set(permitted) & parser_control:
        raise ValueError("worker permitted-opcode table is not canonical")
    if not set(permitted) <= defined:
        raise ValueError("worker permits an undefined opcode")
    prohibited = sorted(defined - set(permitted) - parser_control)
    explicitly_prohibited = {opcode.opmap[name] for name in EXPLICITLY_PROHIBITED_NAMES}
    if not explicitly_prohibited <= set(prohibited):
        raise ValueError("worker omits an explicit Amendment-5 prohibition")
    if set(permitted) | set(prohibited) | parser_control != defined:
        raise ValueError("defined opcode partition is incomplete")

    oracle_name_operand_rules = [
        [value, 1 if value == opcode.opmap["LOAD_GLOBAL"] else 0]
        for value in sorted(opcode.hasname)
    ]
    if type(worker_name_rules) is not dict or any(
        type(key) is not int or type(value) is not int
        for key, value in worker_name_rules.items()
    ):
        raise ValueError("worker co_names index-rule table is invalid")
    worker_name_operand_rules = [
        [value, worker_name_rules[value]] for value in sorted(worker_name_rules)
    ]
    if worker_name_operand_rules != oracle_name_operand_rules:
        raise ValueError("worker co_names opcode classification differs from pinned CPython")
    executable_name_opcodes = name_opcodes | attribute_opcodes
    if executable_name_opcodes != set(worker_name_rules) & set(permitted):
        raise ValueError("worker executable co_names tables differ from policy commitment")
    expected_write_names = {
        opcode.opmap[name]
        for name in ("STORE_NAME", "DELETE_NAME", "STORE_GLOBAL", "DELETE_GLOBAL")
    }
    if write_name_opcodes != expected_write_names:
        raise ValueError("worker name-write table differs from pinned policy")
    if forbidden_names != EXPECTED_FORBIDDEN_NAMES:
        raise ValueError("worker forbidden-name table differs from Amendment 5")
    if permitted_attributes != EXPECTED_PERMITTED_ATTRIBUTES:
        raise ValueError("worker attribute allowlist differs from Amendment 5")
    expected_relative_jumps = set(opcode.hasjrel) & set(permitted)
    expected_backward_jumps = {
        value for value in expected_relative_jumps if "BACKWARD" in opcode.opname[value]
    }
    if backward_jumps != expected_backward_jumps:
        raise ValueError("worker backward-jump table differs from pinned CPython")
    if forward_jumps != expected_relative_jumps - expected_backward_jumps:
        raise ValueError("worker forward-jump table differs from pinned CPython")
    if fast_opcodes != set(opcode.haslocal) & set(permitted):
        raise ValueError("worker local-operand table differs from pinned CPython")
    if localsplus_opcodes != set(opcode.hasfree) & set(permitted):
        raise ValueError("worker locals-plus table differs from pinned CPython")
    name_operand_rules = oracle_name_operand_rules
    policy = [
        bytes.fromhex(base_root),
        bytes.fromhex(cache_root),
        permitted,
        prohibited,
        name_operand_rules,
    ]
    policy_root = sha256(
        _cbor([b"V631302_WORKER_OPCODE_POLICY_V1", 631302, 1, policy])
    ).hexdigest()

    inventory_rows: list[list[object]] = []
    input_rows: list[list[object]] = [
        ["/proc/self/exe", INTERPRETER_SIZE, bytes.fromhex(INTERPRETER_SHA256)],
        [str(OPCODE_ORACLE_PATH), len(oracle_raw), bytes.fromhex(oracle_digest)],
        [str(WORKER_PATH.relative_to(ROOT)), len(worker_raw), bytes.fromhex(worker_digest)],
    ]
    observed_opcodes: set[int] = set()
    for relative in PROJECT_PATHS:
        source, source_digest = _bytes(ROOT / relative)
        input_rows.append([relative, len(source), bytes.fromhex(source_digest)])
        module = compile(
            source,
            "v631302-bundle://" + relative,
            "exec",
            flags=0,
            dont_inherit=True,
            optimize=0,
        )
        for code_path, code in _walk(module):
            instructions = _instruction_rows(
                code.co_code,
                defined=defined,
                cache_widths=cache_widths,
            )
            counts = Counter(row[1] for row in instructions)
            if not set(counts) <= set(permitted):
                raise ValueError(f"project code uses prohibited opcode: {relative} {code_path}")
            observed_opcodes.update(counts)
            inventory_rows.append(
                [
                    relative,
                    list(code_path),
                    code.co_name,
                    instructions,
                    [[value, counts[value]] for value in sorted(counts)],
                    len(code.co_code),
                    sha256(code.co_code).digest(),
                ]
            )
    input_rows.sort(key=lambda row: str(row[0]).encode("utf-8"))
    inventory_rows.sort(key=lambda row: _cbor(row[:2]))
    input_manifest_root = _root(
        b"V631302_WORKER_POLICY_REFERENCE_INPUTS_V1",
        input_rows,
    )
    inventory_root = _root(
        b"V631302_RECURSIVE_BUNDLE_BYTECODE_INVENTORY_V1",
        inventory_rows,
    )
    script_raw, script_digest = _bytes(Path(__file__).resolve())
    return {
        "schema": "V631302_WORKER_BYTECODE_POLICY_PROOF_V1",
        "protocol": 631302,
        "proof_result": 1,
        "interpreter_record": [
            interpreter_record[0],
            interpreter_record[1],
            interpreter_record[2],
            interpreter_record[3],
            interpreter_record[4].hex(),
        ],
        "opcode_oracle": {
            "path": str(OPCODE_ORACLE_PATH),
            "byte_length": len(oracle_raw),
            "sha256": oracle_digest,
        },
        "base_opcode_map_root": base_root,
        "inline_cache_widths_root": cache_root,
        "worker_opcode_policy_root": policy_root,
        "reference_extractor": {
            "path": str(Path(__file__).resolve().relative_to(ROOT)),
            "byte_length": len(script_raw),
            "sha256": script_digest,
        },
        "reference_input_manifest_root": input_manifest_root,
        "recursive_bundle_bytecode_inventory_root": inventory_root,
        "worker": {
            "path": str(WORKER_PATH.relative_to(ROOT)),
            "byte_length": len(worker_raw),
            "sha256": worker_digest,
        },
        "permitted_executable_opcodes": permitted,
        "prohibited_executable_opcodes": prohibited,
        "name_operand_rules": name_operand_rules,
        "observed_project_opcodes": sorted(observed_opcodes),
        "worker_security_tables_result": 1,
        "input_rows": [
            [row[0], row[1], row[2].hex()]
            for row in input_rows
        ],
        "inventory_rows": [
            [row[0], row[1], row[2], row[3], row[4], row[5], row[6].hex()]
            for row in inventory_rows
        ],
    }


def main() -> int:
    print(json.dumps(verify(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
