"""Authority-free, descriptor-bound implementation manifests for MCI_TRANSFER_V1.

This module only binds source bytes and interpreter package versions.  It does
not inspect outcomes, fit models, inspect holdouts, or authorize submissions.
The manifest's self digest is the canonical SHA-256 of the manifest with its
``manifest_sha256`` member omitted; this is the usual non-recursive meaning of
a self hash.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import sysconfig
from typing import Any

from .canonical import canonical_json_bytes, canonical_sha256


PROTOCOL_ID = "MCI_TRANSFER_V1"
MANIFEST_SCHEMA_VERSION = 4
MANIFEST_SCHEMA = f"evaluation_v5_implementation_binding_v{MANIFEST_SCHEMA_VERSION}"
AUTHORITY = False

_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "architecture_binding_sha256",
        "created_at_utc",
        "files",
        "runtime",
        "authority",
        "manifest_sha256",
    }
)
_FILE_FIELDS = frozenset({"path", "sha256"})
_RUNTIME_PACKAGES = {
    "cryptography": "cryptography",
    "joblib": "joblib",
    "numpy": "numpy",
    "scipy": "scipy",
    "sklearn": "scikit-learn",
    "threadpoolctl": "threadpoolctl",
}
_RUNTIME_FIELDS = frozenset(
    {
        "python",
        "python_executable_sha256",
        "python_stdlib_sha256",
        *(_RUNTIME_PACKAGES),
        *(f"{name}_distribution_sha256" for name in _RUNTIME_PACKAGES),
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


class ImplementationBindingError(ValueError):
    """The implementation manifest or its bound files is invalid."""


ManifestVerificationError = ImplementationBindingError


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ImplementationBindingError(f"{label} fields are not exact")
    return value


def _digest(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ImplementationBindingError(f"{label} is not a lowercase SHA-256 digest")
    return value


def normalize_repo_relative_path(value: object) -> str:
    """Validate and return a normalized, repository-relative POSIX path."""

    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise ImplementationBindingError("file path is not a safe relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ImplementationBindingError("file path is not a safe relative POSIX path")
    if path.as_posix() != value:
        raise ImplementationBindingError("file path is not normalized")
    return value


def _canonical_created_at(value: object) -> str:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise ImplementationBindingError("created_at_utc is not canonical six-microsecond UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ImplementationBindingError("created_at_utc is not a valid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise ImplementationBindingError("created_at_utc is not canonical six-microsecond UTC")
    return value


def _created_at(value: str | datetime | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ImplementationBindingError("created_at_utc datetime must be timezone-aware")
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return _canonical_created_at(value)


def _hash_runtime_file(path: Path) -> str:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImplementationBindingError("runtime file cannot be resolved") from exc
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise ImplementationBindingError("runtime file cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ImplementationBindingError("runtime path is not a regular file")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ImplementationBindingError("runtime file cannot be read safely") from exc
    finally:
        os.close(descriptor)
    if total != before.st_size or _stat_identity(before) != _stat_identity(after):
        raise ImplementationBindingError("runtime file changed while it was hashed")
    return digest.hexdigest()


def _runtime_tree_digest(files: Iterable[tuple[str, Path]]) -> str:
    records = [
        {"path": relative, "sha256": _hash_runtime_file(path)}
        for relative, path in sorted(files)
    ]
    if not records:
        raise ImplementationBindingError("runtime content set is empty")
    return canonical_sha256(records)


def _stdlib_digest() -> str:
    try:
        root = Path(sysconfig.get_paths()["stdlib"]).resolve(strict=True)
    except (KeyError, OSError, RuntimeError) as exc:
        raise ImplementationBindingError("Python standard library cannot be resolved") from exc
    selected: list[tuple[str, Path]] = []
    for path in root.rglob("*"):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if "site-packages" in relative.parts or "__pycache__" in relative.parts:
            continue
        if path.is_file():
            selected.append((relative.as_posix(), path))
    return _runtime_tree_digest(selected)


def _distribution_digest(distribution_name: str) -> str:
    try:
        distribution = importlib.metadata.distribution(distribution_name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise ImplementationBindingError(
            f"runtime package {distribution_name} is unavailable"
        ) from exc
    selected: list[tuple[str, Path]] = []
    for package_path in distribution.files or ():
        relative = package_path.as_posix()
        if "__pycache__" in package_path.parts:
            continue
        located = Path(distribution.locate_file(package_path))
        if located.is_file():
            selected.append((relative, located))
    return _runtime_tree_digest(selected)


def runtime_versions() -> dict[str, str]:
    """Return interpreter identity and package versions used by this binding."""

    executable = Path(sys.executable).resolve(strict=True)
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(executable, flags)
    try:
        before = os.fstat(descriptor)
        for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _stat_identity(before) != _stat_identity(after):
        raise ImplementationBindingError("Python executable changed while it was hashed")
    versions: dict[str, str] = {
        "python": platform.python_version(),
        "python_executable_sha256": digest.hexdigest(),
        "python_stdlib_sha256": _stdlib_digest(),
    }
    for key, distribution in _RUNTIME_PACKAGES.items():
        try:
            version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise ImplementationBindingError(f"runtime package {distribution} is unavailable") from exc
        versions[key] = version
        versions[f"{key}_distribution_sha256"] = _distribution_digest(distribution)
    return versions


def _validate_runtime(value: object) -> dict[str, str]:
    raw = _exact_fields(value, _RUNTIME_FIELDS, label="runtime")
    result: dict[str, str] = {}
    for name in sorted(_RUNTIME_FIELDS):
        version = raw[name]
        if type(version) is not str or not version:
            raise ImplementationBindingError(f"runtime {name} version is invalid")
        if name.endswith("_sha256"):
            _digest(version, label=name)
        result[name] = version
    return result


def _manifest_content(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": manifest["schema"],
        "protocol_id": manifest["protocol_id"],
        "architecture_binding_sha256": manifest["architecture_binding_sha256"],
        "created_at_utc": manifest["created_at_utc"],
        "files": manifest["files"],
        "runtime": manifest["runtime"],
        "authority": manifest["authority"],
    }


def manifest_sha256(manifest: object) -> str:
    """Compute the non-recursive canonical self hash of a valid manifest."""

    checked = validate_manifest(manifest, check_self_hash=False)
    return canonical_sha256(_manifest_content(checked))


def validate_manifest(manifest: object, *, check_self_hash: bool = True) -> dict[str, Any]:
    """Validate manifest structure, canonical values, ordering, and self hash."""

    raw = _exact_fields(manifest, _MANIFEST_FIELDS, label="implementation manifest")
    if raw["schema"] != MANIFEST_SCHEMA or type(raw["schema"]) is not str:
        raise ImplementationBindingError("manifest schema mismatch")
    if raw["protocol_id"] != PROTOCOL_ID or type(raw["protocol_id"]) is not str:
        raise ImplementationBindingError("manifest protocol id mismatch")
    _digest(raw["architecture_binding_sha256"], label="architecture_binding_sha256")
    created_at = _canonical_created_at(raw["created_at_utc"])
    if raw["authority"] is not AUTHORITY:
        raise ImplementationBindingError("implementation binding authority must be false")

    if not isinstance(raw["files"], list) or not raw["files"]:
        raise ImplementationBindingError("manifest files must be a non-empty ordered list")
    files: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw["files"]):
        record = _exact_fields(item, _FILE_FIELDS, label=f"file record {index}")
        path = normalize_repo_relative_path(record["path"])
        if path in seen:
            raise ImplementationBindingError("manifest contains duplicate file paths")
        seen.add(path)
        files.append({"path": path, "sha256": _digest(record["sha256"], label=f"file record {index} sha256")})

    runtime = _validate_runtime(raw["runtime"])
    self_digest = _digest(raw["manifest_sha256"], label="manifest_sha256")
    checked = {
        "schema": MANIFEST_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "architecture_binding_sha256": raw["architecture_binding_sha256"],
        "created_at_utc": created_at,
        "files": files,
        "runtime": runtime,
        "authority": False,
        "manifest_sha256": self_digest,
    }
    if check_self_hash and self_digest != canonical_sha256(_manifest_content(checked)):
        raise ImplementationBindingError("manifest self hash mismatch")
    return checked


def _root_path(repo_root: str | Path) -> Path:
    try:
        root = Path(repo_root).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImplementationBindingError("repository root does not exist") from exc
    if not root.is_dir():
        raise ImplementationBindingError("repository root is not a directory")
    return root


def _nofollow_flags(*, directory: bool = False) -> int:
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        if directory:
            flags |= os.O_DIRECTORY
    except AttributeError as exc:
        raise ImplementationBindingError("platform lacks required no-follow open flags") from exc
    return flags


def _fd_path(fd: int, *, fallback: Path | None = None) -> Path:
    for prefix in ("/proc/self/fd", "/dev/fd"):
        try:
            target = os.readlink(f"{prefix}/{fd}")
        except OSError:
            continue
        if target.endswith(" (deleted)"):
            raise ImplementationBindingError("opened file was unlinked during verification")
        try:
            return Path(target).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ImplementationBindingError("opened descriptor has no stable path") from exc
    if fallback is not None:
        try:
            return fallback.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ImplementationBindingError("opened descriptor has no stable path") from exc
    raise ImplementationBindingError("cannot resolve opened descriptor")


def _under_root(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ImplementationBindingError("opened file escapes repository root") from exc


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _hash_open_descriptor(fd: int, *, root: Path, opened_path: Path) -> str:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise ImplementationBindingError("bound path is not a regular file")
    _under_root(_fd_path(fd, fallback=opened_path), root)
    digest = hashlib.sha256()
    total = 0
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    finally:
        after = os.fstat(fd)
    if total != before.st_size or _stat_identity(before) != _stat_identity(after):
        raise ImplementationBindingError("bound file changed while it was hashed")
    _under_root(_fd_path(fd, fallback=opened_path), root)
    return digest.hexdigest()


def _open_repo_file(root_fd: int, root: Path, relative_path: str) -> int:
    parts = PurePosixPath(relative_path).parts
    try:
        resolved_target = (root / Path(*parts)).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImplementationBindingError("bound file does not resolve safely") from exc
    _under_root(resolved_target, root)
    current_fd = os.dup(root_fd)
    file_fd: int | None = None
    keep_open = False
    try:
        for index, component in enumerate(parts[:-1]):
            next_fd = os.open(component, _nofollow_flags(directory=True), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
            directory_stat = os.fstat(current_fd)
            if not stat.S_ISDIR(directory_stat.st_mode):
                raise ImplementationBindingError("file path contains a non-directory component")
            fallback = (root / Path(*parts[: index + 1])).resolve(strict=True)
            _under_root(_fd_path(current_fd, fallback=fallback), root)
        file_fd = os.open(parts[-1], _nofollow_flags(), dir_fd=current_fd)
        _under_root(_fd_path(file_fd, fallback=resolved_target), root)
        keep_open = True
        return file_fd
    except OSError as exc:
        raise ImplementationBindingError("bound file cannot be opened without following links") from exc
    finally:
        os.close(current_fd)
        if file_fd is not None and not keep_open:
            os.close(file_fd)


def _hash_repo_file(root_fd: int, root: Path, relative_path: str) -> str:
    fd = _open_repo_file(root_fd, root, relative_path)
    opened_path = (root / Path(*PurePosixPath(relative_path).parts)).resolve(strict=True)
    try:
        return _hash_open_descriptor(fd, root=root, opened_path=opened_path)
    except OSError as exc:
        raise ImplementationBindingError("bound file cannot be hashed") from exc
    finally:
        os.close(fd)


def _open_root(root: Path) -> int:
    fd: int | None = None
    try:
        fd = os.open(root, _nofollow_flags(directory=True))
        root_opened = _fd_path(fd, fallback=root)
        _under_root(root_opened, root)
        if root_opened != root:
            raise ImplementationBindingError("opened repository root does not match resolved root")
        return fd
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        raise ImplementationBindingError("repository root cannot be opened safely") from exc
    except ImplementationBindingError:
        if fd is not None:
            os.close(fd)
        raise


def verify_manifest(
    repo_root: str | Path,
    manifest: object,
    *,
    required_paths: Iterable[str | Path] | None = None,
) -> dict[str, Any]:
    """Verify runtime identity and hashes from already-opened descriptors."""

    checked = validate_manifest(manifest)
    if required_paths is not None:
        normalized_required = [
            normalize_repo_relative_path(
                value.as_posix() if isinstance(value, Path) else value
            )
            for value in required_paths
        ]
        if len(normalized_required) != len(set(normalized_required)):
            raise ImplementationBindingError("required implementation paths contain duplicates")
        actual_paths = [record["path"] for record in checked["files"]]
        if actual_paths != normalized_required:
            raise ImplementationBindingError(
                "implementation binding does not contain the exact required file set"
            )
    if checked["runtime"] != runtime_versions():
        raise ImplementationBindingError("runtime version mismatch")
    root = _root_path(repo_root)
    try:
        root_fd = _open_root(root)
    except ImplementationBindingError:
        raise
    try:
        for record in checked["files"]:
            actual = _hash_repo_file(root_fd, root, record["path"])
            if actual != record["sha256"]:
                raise ImplementationBindingError(f"digest mismatch for {record['path']}")
    finally:
        os.close(root_fd)
    return checked


def build_manifest(
    repo_root: str | Path,
    architecture_binding_sha256: str,
    paths: Iterable[str | Path] | None = None,
    *,
    created_at_utc: str | datetime | None = None,
    runtime: Mapping[str, str] | None = None,
    file_paths: Iterable[str | Path] | None = None,
) -> dict[str, Any]:
    """Build a manifest by hashing an ordered, explicit list of repository files."""

    architecture_digest = _digest(architecture_binding_sha256, label="architecture_binding_sha256")
    if paths is not None and file_paths is not None:
        raise ImplementationBindingError("paths and file_paths cannot both be supplied")
    selected = paths if paths is not None else file_paths
    if selected is None:
        raise ImplementationBindingError("an explicit file path list is required")
    normalized: list[str] = []
    seen: set[str] = set()
    for value in selected:
        if isinstance(value, Path):
            value = value.as_posix()
        path = normalize_repo_relative_path(value)
        if path in seen:
            raise ImplementationBindingError("manifest contains duplicate file paths")
        seen.add(path)
        normalized.append(path)
    if not normalized:
        raise ImplementationBindingError("manifest files must be non-empty")

    root = _root_path(repo_root)
    root_fd = _open_root(root)
    try:
        files = [{"path": path, "sha256": _hash_repo_file(root_fd, root, path)} for path in normalized]
    finally:
        os.close(root_fd)

    runtime_record = _validate_runtime(runtime if runtime is not None else runtime_versions())
    content = {
        "schema": MANIFEST_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "architecture_binding_sha256": architecture_digest,
        "created_at_utc": _created_at(created_at_utc),
        "files": files,
        "runtime": runtime_record,
        "authority": False,
    }
    content["manifest_sha256"] = canonical_sha256(content)
    return validate_manifest(content)


def write_manifest_once(path: str | Path, manifest: object) -> None:
    """Create a canonical manifest file exactly once, with durable flushing."""

    checked = validate_manifest(manifest)
    payload = canonical_json_bytes(checked)
    destination = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(destination, flags, 0o644)
    except (AttributeError, OSError) as exc:
        raise ImplementationBindingError("manifest destination already exists or cannot be created safely") from exc
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(fd, payload[offset:])
        os.fsync(fd)
    except OSError as exc:
        raise ImplementationBindingError("manifest cannot be durably written") from exc
    finally:
        os.close(fd)
    try:
        parent_fd = os.open(destination.parent, _nofollow_flags(directory=True))
    except OSError as exc:
        raise ImplementationBindingError("manifest parent cannot be durably flushed") from exc
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Load and validate a JSON manifest; this does not verify repository files."""

    try:
        with Path(path).open("rb") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ImplementationBindingError("manifest JSON cannot be read") from exc
    return validate_manifest(value)


build_implementation_manifest = build_manifest
build_implementation_binding = build_manifest
validate_implementation_manifest = validate_manifest
verify_implementation_manifest = verify_manifest
write_implementation_manifest_once = write_manifest_once
write_manifest = write_manifest_once
read_manifest = load_manifest
implementation_manifest_sha256 = manifest_sha256


__all__ = [
    "AUTHORITY",
    "MANIFEST_SCHEMA",
    "MANIFEST_SCHEMA_VERSION",
    "ManifestVerificationError",
    "ImplementationBindingError",
    "PROTOCOL_ID",
    "build_implementation_manifest",
    "build_implementation_binding",
    "build_manifest",
    "implementation_manifest_sha256",
    "load_manifest",
    "manifest_sha256",
    "normalize_repo_relative_path",
    "read_manifest",
    "runtime_versions",
    "validate_implementation_manifest",
    "validate_manifest",
    "verify_implementation_manifest",
    "verify_manifest",
    "write_manifest",
    "write_implementation_manifest_once",
    "write_manifest_once",
]
