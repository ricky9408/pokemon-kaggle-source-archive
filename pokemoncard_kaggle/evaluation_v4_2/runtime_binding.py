"""Build and verify the local runtime receipt used by evaluation v4.2.

The receipt grants no scientific or submission authority.  It only proves that
the interpreter, installed distributions, and imported evaluator source trees
match the bytes frozen in a simulation template.
"""

from __future__ import annotations

import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import re
import sys
from typing import Any, Mapping

from .simulation_design import canonical_sha256


RUNTIME_BINDING_SCHEMA = "evaluation_v4_2_runtime_binding_v1"
REQUIRED_SOURCE_TREES = frozenset({"evaluation_v2", "evaluation_v4_2"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "python_implementation",
        "python_version",
        "python_executable",
        "python_executable_sha256",
        "platform_system",
        "platform_machine",
        "distributions",
        "source_trees",
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}
_TREE_FIELDS = frozenset({"logical_name", "path", "python_tree_sha256"})


class RuntimeBindingError(ValueError):
    """The runtime receipt does not match the executing environment."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def python_tree_sha256(path: Path) -> str:
    """Hash relative paths and bytes for every non-cache Python source file."""

    root = path.resolve()
    if root.is_symlink() or not root.is_dir():
        raise RuntimeBindingError(f"Python source tree is not a regular directory: {root}")
    records: list[dict[str, str]] = []
    for item in sorted(root.rglob("*.py"), key=lambda value: value.relative_to(root).as_posix()):
        if item.is_symlink() or not item.is_file():
            raise RuntimeBindingError(f"Python source tree contains an invalid entry: {item}")
        if "__pycache__" in item.parts:
            continue
        records.append(
            {
                "path": item.relative_to(root).as_posix(),
                "sha256": sha256_file(item),
            }
        )
    if not records:
        raise RuntimeBindingError(f"Python source tree has no .py files: {root}")
    encoded = json.dumps(
        records, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def installed_distributions() -> dict[str, str]:
    values: dict[str, str] = {}
    for distribution in metadata.distributions():
        name = str(distribution.metadata.get("Name") or "").strip().lower()
        if not name:
            continue
        version = str(distribution.version)
        previous = values.get(name)
        if previous is not None and previous != version:
            raise RuntimeBindingError(f"distribution {name!r} has conflicting versions")
        values[name] = version
    return dict(sorted(values.items()))


def _runtime_content(source_trees: Mapping[str, Path]) -> dict[str, Any]:
    if set(source_trees) != REQUIRED_SOURCE_TREES:
        raise RuntimeBindingError(
            f"source trees must exactly be {sorted(REQUIRED_SOURCE_TREES)}"
        )
    executable = Path(sys.executable).resolve()
    if not executable.is_file():
        raise RuntimeBindingError(f"Python executable does not exist: {executable}")
    trees = [
        {
            "logical_name": logical_name,
            "path": str(source_trees[logical_name].resolve()),
            "python_tree_sha256": python_tree_sha256(source_trees[logical_name]),
        }
        for logical_name in sorted(source_trees)
    ]
    return {
        "schema": RUNTIME_BINDING_SCHEMA,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable": str(executable),
        "python_executable_sha256": sha256_file(executable),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "distributions": installed_distributions(),
        "source_trees": trees,
    }


def build_runtime_binding(source_trees: Mapping[str, Path]) -> dict[str, Any]:
    content = _runtime_content(source_trees)
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_runtime_binding(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise RuntimeBindingError(f"runtime binding fields must exactly be {sorted(_FIELDS)}")
    content = {key: value[key] for key in _CONTENT_FIELDS}
    if value.get("schema") != RUNTIME_BINDING_SCHEMA:
        raise RuntimeBindingError(f"runtime binding schema must be {RUNTIME_BINDING_SCHEMA!r}")
    digest = value.get("content_sha256")
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise RuntimeBindingError("runtime binding content_sha256 is invalid")
    if digest != canonical_sha256(content):
        raise RuntimeBindingError("runtime binding content_sha256 mismatch")
    trees = value.get("source_trees")
    if not isinstance(trees, list):
        raise RuntimeBindingError("runtime binding source_trees must be a list")
    source_paths: dict[str, Path] = {}
    for row in trees:
        if not isinstance(row, Mapping) or set(row) != _TREE_FIELDS:
            raise RuntimeBindingError("runtime binding source-tree fields are invalid")
        logical_name = row.get("logical_name")
        path = row.get("path")
        tree_digest = row.get("python_tree_sha256")
        if not isinstance(logical_name, str) or logical_name in source_paths:
            raise RuntimeBindingError("runtime binding source-tree names are invalid")
        if not isinstance(path, str) or not path:
            raise RuntimeBindingError("runtime binding source-tree path is invalid")
        if not isinstance(tree_digest, str) or _SHA256_RE.fullmatch(tree_digest) is None:
            raise RuntimeBindingError("runtime binding source-tree digest is invalid")
        source_paths[logical_name] = Path(path)
    expected = build_runtime_binding(source_paths)
    if dict(value) != expected:
        raise RuntimeBindingError("runtime binding does not match current runtime bytes")
    return expected


def validate_runtime_binding_file(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeBindingError(f"could not read runtime binding {path}: {exc}") from exc
    return validate_runtime_binding(payload)


__all__ = [
    "RUNTIME_BINDING_SCHEMA",
    "RuntimeBindingError",
    "build_runtime_binding",
    "installed_distributions",
    "python_tree_sha256",
    "sha256_file",
    "validate_runtime_binding",
    "validate_runtime_binding_file",
]
