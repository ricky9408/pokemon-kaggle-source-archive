"""Frozen executable identity for authenticated Kaggle evidence and uploads."""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
from typing import Any, Mapping

from .protocol import canonical_sha256


RUNTIME_BINDING_SCHEMA = "voi_p5_kaggle_runtime_binding_v4"
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "workspace_root",
        "uv_executable",
        "uv_executable_sha256",
        "kaggle_entrypoint",
        "kaggle_entrypoint_sha256",
        "python_entrypoint",
        "python_entrypoint_sha256",
        "python_entrypoint_link_target",
        "python_executable",
        "python_executable_sha256",
        "kaggle_package_root",
        "kaggle_package_tree_sha256",
        "kaggle_record_path",
        "kaggle_record_sha256",
        "evaluation_package_root",
        "evaluation_package_tree_sha256",
        "byte_bridge_path",
        "byte_bridge_sha256",
        "capture_module_path",
        "capture_module_sha256",
        "research_only",
        "production_submission_authorized",
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}


class RuntimeBindingError(ValueError):
    """The pinned Kaggle runtime changed or is malformed."""


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_sha(root: Path) -> str:
    records = []
    for path in sorted((path for path in root.rglob("*") if path.is_file()), key=lambda item: item.as_posix()):
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": _sha_file(path),
            }
        )
    if not records:
        raise RuntimeBindingError("Kaggle package tree is empty")
    return canonical_sha256(records)


def _python_tree_sha(root: Path) -> str:
    records = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha_file(path),
        }
        for path in sorted(root.rglob("*.py"), key=lambda item: item.as_posix())
        if path.is_file() and "__pycache__" not in path.parts
    ]
    if not records:
        raise RuntimeBindingError("evaluation source tree is empty")
    return canonical_sha256(records)


def _derive(
    *,
    workspace_root: str | Path,
    uv_executable: str | Path,
    kaggle_entrypoint: str | Path,
    python_entrypoint: str | Path,
    python_executable: str | Path,
    kaggle_package_root: str | Path,
    kaggle_record_path: str | Path,
    evaluation_package_root: str | Path,
    byte_bridge_path: str | Path,
    capture_module_path: str | Path,
) -> dict[str, Any]:
    workspace = Path(workspace_root).expanduser().resolve(strict=True)
    uv = Path(uv_executable).expanduser().resolve(strict=True)
    kaggle = Path(kaggle_entrypoint).expanduser().resolve(strict=True)
    python_entry = Path(python_entrypoint).expanduser().absolute()
    python = Path(python_executable).expanduser().resolve(strict=True)
    package = Path(kaggle_package_root).expanduser().resolve(strict=True)
    record = Path(kaggle_record_path).expanduser().resolve(strict=True)
    evaluation_package = Path(evaluation_package_root).expanduser().resolve(strict=True)
    byte_bridge = Path(byte_bridge_path).expanduser().resolve(strict=True)
    capture = Path(capture_module_path).expanduser().resolve(strict=True)
    if not workspace.is_dir() or not package.is_dir() or not evaluation_package.is_dir():
        raise RuntimeBindingError("workspace and frozen package roots must be directories")
    for path in (uv, kaggle, python_entry, python, record, byte_bridge, capture):
        if not path.is_file():
            raise RuntimeBindingError(f"runtime component is not a file: {path}")
    if (
        workspace not in kaggle.parents
        or workspace not in package.parents
        or workspace not in evaluation_package.parents
    ):
        raise RuntimeBindingError("runtime components must live under the frozen workspace")
    return {
        "schema": RUNTIME_BINDING_SCHEMA,
        "workspace_root": str(workspace),
        "uv_executable": str(uv),
        "uv_executable_sha256": _sha_file(uv),
        "kaggle_entrypoint": str(kaggle),
        "kaggle_entrypoint_sha256": _sha_file(kaggle),
        "python_entrypoint": str(python_entry),
        "python_entrypoint_sha256": _sha_file(python_entry),
        "python_entrypoint_link_target": str(python_entry.resolve(strict=True)),
        "python_executable": str(python),
        "python_executable_sha256": _sha_file(python),
        "kaggle_package_root": str(package),
        "kaggle_package_tree_sha256": _tree_sha(package),
        "kaggle_record_path": str(record),
        "kaggle_record_sha256": _sha_file(record),
        "evaluation_package_root": str(evaluation_package),
        "evaluation_package_tree_sha256": _python_tree_sha(evaluation_package),
        "byte_bridge_path": str(byte_bridge),
        "byte_bridge_sha256": _sha_file(byte_bridge),
        "capture_module_path": str(capture),
        "capture_module_sha256": _sha_file(capture),
        "research_only": True,
        "production_submission_authorized": False,
    }


def build_kaggle_runtime_binding(
    workspace_root: str | Path,
    *,
    uv_executable: str | Path | None = None,
) -> dict[str, Any]:
    workspace = Path(workspace_root).expanduser().resolve(strict=True)
    uv_path = uv_executable or shutil.which("uv")
    if uv_path is None:
        raise RuntimeBindingError("uv executable is unavailable")
    site_packages = workspace / ".venv" / "lib" / "python3.11" / "site-packages"
    records = sorted(site_packages.glob("kaggle-*.dist-info/RECORD"))
    if len(records) != 1:
        raise RuntimeBindingError("exactly one Kaggle distribution RECORD is required")
    content = _derive(
        workspace_root=workspace,
        uv_executable=uv_path,
        kaggle_entrypoint=workspace / ".venv" / "bin" / "kaggle",
        python_entrypoint=workspace / ".venv" / "bin" / "python3",
        python_executable=(workspace / ".venv" / "bin" / "python3").resolve(strict=True),
        kaggle_package_root=site_packages / "kaggle",
        kaggle_record_path=records[0],
        evaluation_package_root=workspace / "evaluation_v4_1",
        byte_bridge_path=workspace / "evaluation_v4_1" / "kaggle_bytes_bridge.py",
        capture_module_path=workspace / "evaluation_v4_1" / "kaggle_evidence.py",
    )
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_kaggle_runtime_binding(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise RuntimeBindingError("Kaggle runtime binding fields are not exact")
    raw = dict(value)
    if raw["schema"] != RUNTIME_BINDING_SCHEMA:
        raise RuntimeBindingError("Kaggle runtime binding schema mismatch")
    expected = _derive(
        workspace_root=raw["workspace_root"],
        uv_executable=raw["uv_executable"],
        kaggle_entrypoint=raw["kaggle_entrypoint"],
        python_entrypoint=raw["python_entrypoint"],
        python_executable=raw["python_executable"],
        kaggle_package_root=raw["kaggle_package_root"],
        kaggle_record_path=raw["kaggle_record_path"],
        evaluation_package_root=raw["evaluation_package_root"],
        byte_bridge_path=raw["byte_bridge_path"],
        capture_module_path=raw["capture_module_path"],
    )
    if {field: raw[field] for field in _CONTENT_FIELDS} != expected:
        raise RuntimeBindingError("Kaggle runtime binding no longer matches exact files")
    if raw["content_sha256"] != canonical_sha256(expected):
        raise RuntimeBindingError("Kaggle runtime binding content SHA-256 mismatch")
    return {**expected, "content_sha256": raw["content_sha256"]}


__all__ = [
    "RUNTIME_BINDING_SCHEMA",
    "RuntimeBindingError",
    "build_kaggle_runtime_binding",
    "validate_kaggle_runtime_binding",
]
