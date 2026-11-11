"""Build and inspect deterministic, cache-free submission archives."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import tarfile
from pathlib import Path


REQUIRED_ROOT_FILES = {"main.py", "deck.csv"}
FORBIDDEN_PARTS = {"__pycache__", ".DS_Store"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _eligible_files(agent_dir: Path) -> list[Path]:
    files: list[Path] = []
    for path in agent_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(agent_dir)
        if any(part in FORBIDDEN_PARTS or part.startswith("._") for part in relative.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        files.append(path)
    return sorted(files, key=lambda path: str(path.relative_to(agent_dir)))


def build_archive(agent_dir: Path, output: Path) -> str:
    agent_dir = agent_dir.resolve()
    root_names = {path.name for path in agent_dir.iterdir() if path.is_file()}
    missing = REQUIRED_ROOT_FILES - root_names
    if missing:
        raise ValueError(f"agent is missing required files: {sorted(missing)}")
    files = _eligible_files(agent_dir)
    if not any(path.relative_to(agent_dir).parts[0] == "cg" for path in files):
        raise ValueError("agent archive has no cg package")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in files:
                    relative = path.relative_to(agent_dir)
                    info = archive.gettarinfo(str(path), arcname=str(relative))
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    with path.open("rb") as handle:
                        archive.addfile(info, handle)
    errors = inspect_archive(output)
    if errors:
        output.unlink(missing_ok=True)
        raise ValueError("invalid archive: " + "; ".join(errors))
    return sha256_file(output)


def inspect_archive(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
    except (OSError, tarfile.TarError) as exc:
        return [f"archive cannot be read: {exc}"]
    names = [member.name for member in members]
    roots = {name for name in names if "/" not in name}
    missing = REQUIRED_ROOT_FILES - roots
    if missing:
        errors.append(f"missing root files: {sorted(missing)}")
    if not any(name.startswith("cg/") for name in names):
        errors.append("missing cg package")
    for name in names:
        path_parts = Path(name).parts
        if name.startswith("/") or ".." in path_parts:
            errors.append(f"unsafe member: {name}")
        if any(part in FORBIDDEN_PARTS or part.startswith("._") for part in path_parts):
            errors.append(f"cache/metadata member: {name}")
        if name.endswith((".pyc", ".pyo")):
            errors.append(f"bytecode member: {name}")
    return sorted(set(errors))


def materialize_archive(path: Path, destination: Path) -> None:
    errors = inspect_archive(path)
    if errors:
        raise ValueError("invalid archive: " + "; ".join(errors))
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise ValueError(f"unsafe archive member: {member.name}")
        archive.extractall(destination, filter="data")


def source_fingerprints(agent_dir: Path) -> dict[str, str]:
    return {
        "agent_sha256": sha256_file(agent_dir / "main.py"),
        "deck_file_sha256": sha256_file(agent_dir / "deck.csv"),
        "engine_api_sha256": sha256_file(agent_dir / "cg" / "api.py"),
        "engine_native_sha256": sha256_file(agent_dir / "cg" / "libcg.so"),
    }
