#!/usr/bin/env python3
"""Capture a zero-authority provisional v6.3.1 M0 build lock.

This collector records development provenance only.  It deliberately has no
path to a permit, candidate modification, holdout access, or upload authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


SCHEMA = "eval.v6.3.1.m0-provisional-build-lock.v1"
PROTOCOL = "631302"
LLVM_TAG = "llvmorg-16.0.6"
LLVM_COMMIT = "7cbf1a2591520c2491aa35339f227775f4d3adf6"
LLVM_SOURCE_SHA256 = "ce5e71081d17ce9e86d7cbcfa28c4b04b9300f8fb7e78422b1feb6bc52c3028e"
EXPECTED_PLATFORM = "linux/amd64"
EXPECTED_IMAGE_LABELS = {
    "io.garlictoday.evaluation.protocol": PROTOCOL,
    "io.garlictoday.evaluation.authority": "false",
    "io.garlictoday.evaluation.llvm-tag": LLVM_TAG,
    "io.garlictoday.evaluation.llvm-commit": LLVM_COMMIT,
    "io.garlictoday.evaluation.llvm-source-sha256": LLVM_SOURCE_SHA256,
}
CLANG_PATH = "/opt/llvm-build/bin/clang"
CLANGXX_PATH = "/opt/llvm-build/bin/clang++"
CMAKE_CACHE_PATH = "/opt/llvm-build/CMakeCache.txt"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPO_DIGEST_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_CACHE_ENTRY_RE = re.compile(
    r"^(?P<key>[^:=\r\n]+):(?P<type>[^=\r\n]+)=(?P<value>[^\r\n]*)$"
)


class BuildLockError(RuntimeError):
    """A required build-lock fact was absent, malformed, or inconsistent."""


AUTHORITY_BITS = {
    "upload_authorized": False,
    "compiler_recomputed": False,
    "external_evidence_valid": False,
    "eir_freeze_authority": False,
    "engine_wiring_authority": False,
    "campaign_root_authority": False,
    "assignment_authority": False,
    "preregistration_authority": False,
    "permit_authority": False,
    "agent_modification_authority": False,
    "sealed_holdout_access_authority": False,
    "sealed_holdout_access_authorized": False,
    "calibration_upload_authority": False,
    "calibration_upload_authorized": False,
    "production_upload_authority": False,
    "production_upload_authorized": False,
    "compiler_completeness_claimed": False,
    "independent_ab_authority_claimed": False,
}


def _as_bytes(value: Any, label: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise BuildLockError(f"{label} was not text or bytes")


def _text(value: Any, label: str) -> str:
    try:
        return _as_bytes(value, label).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuildLockError(f"{label} was not valid UTF-8") from exc


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    if not command or any(not isinstance(part, str) or not part for part in command):
        raise BuildLockError("Docker command contains an invalid argument")
    try:
        result = subprocess.run(
            list(command),
            capture_output=True,
            check=False,
            shell=False,
            timeout=60.0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildLockError(f"command failed to execute: {command[0]}") from exc
    if result.returncode != 0:
        raise BuildLockError(f"command returned {result.returncode}: {' '.join(command)}")
    stderr = _as_bytes(result.stderr or b"", "command stderr")
    if stderr:
        raise BuildLockError(f"command wrote stderr: {' '.join(command)}")
    return result


def _single_line(result: subprocess.CompletedProcess[bytes], label: str) -> str:
    value = _text(result.stdout, label)
    lines = value.splitlines()
    if len(lines) != 1 or lines[0] != lines[0].strip() or not lines[0]:
        raise BuildLockError(f"{label} was not exactly one non-empty line")
    return lines[0]


def _inspect_image(image: str) -> Mapping[str, Any]:
    result = _run(["docker", "image", "inspect", image])
    try:
        payload = json.loads(_text(result.stdout, "image inspect stdout"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BuildLockError("image inspect output was not valid JSON") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], Mapping):
        raise BuildLockError("image inspect output did not contain exactly one object")
    return payload[0]


def _validate_image_metadata(image: str, metadata: Mapping[str, Any]) -> dict[str, Any]:
    if metadata.get("Os") != "linux" or metadata.get("Architecture") != "amd64":
        raise BuildLockError("Docker image metadata is not linux/amd64")

    image_id = metadata.get("Id")
    if not isinstance(image_id, str) or _IMAGE_ID_RE.fullmatch(image_id) is None:
        raise BuildLockError("Docker image ID is not a SHA-256 image ID")

    repo_digests = metadata.get("RepoDigests", [])
    if not isinstance(repo_digests, list) or any(
        not isinstance(value, str) or _REPO_DIGEST_RE.fullmatch(value) is None
        for value in repo_digests
    ):
        raise BuildLockError("Docker RepoDigests contains a malformed digest")

    config = metadata.get("Config")
    if not isinstance(config, Mapping):
        raise BuildLockError("Docker image Config is absent")
    labels = config.get("Labels")
    if not isinstance(labels, Mapping):
        raise BuildLockError("Docker image labels are absent")
    for key, expected in EXPECTED_IMAGE_LABELS.items():
        if labels.get(key) != expected:
            raise BuildLockError(f"Docker image label mismatch: {key}")

    return {
        "architecture": metadata["Architecture"],
        "id": image_id,
        "labels": {key: labels[key] for key in sorted(EXPECTED_IMAGE_LABELS)},
        "os": metadata["Os"],
        "repo_digests": sorted(repo_digests),
        "reference": image,
    }


def _run_in_image(image: str, command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    return _run(["docker", "run", "--rm", "--platform", EXPECTED_PLATFORM, image, *command])


def _validate_container_architecture(image: str) -> dict[str, str]:
    os_name = _single_line(_run_in_image(image, ["uname", "-s"]), "container uname -s")
    machine = _single_line(_run_in_image(image, ["uname", "-m"]), "container uname -m")
    dpkg_arch = _single_line(
        _run_in_image(image, ["dpkg", "--print-architecture"]),
        "container dpkg architecture",
    )
    if (os_name, machine, dpkg_arch) != ("Linux", "x86_64", "amd64"):
        raise BuildLockError("container did not report linux/amd64")
    return {"dpkg_architecture": dpkg_arch, "machine": machine, "os": os_name}


def _sha256sum_in_image(image: str, path: str) -> str:
    result = _run_in_image(image, ["sha256sum", path])
    line = _single_line(result, f"sha256sum {path}")
    fields = line.split()
    if len(fields) != 2 or fields[1] != path or _SHA256_RE.fullmatch(fields[0]) is None:
        raise BuildLockError(f"sha256sum output mismatch for {path}")
    return fields[0]


def _version_in_image(image: str, path: str) -> str:
    result = _run_in_image(image, [path, "--version"])
    value = _text(result.stdout, f"{path} --version").rstrip("\r\n")
    if not value or "clang version" not in value:
        raise BuildLockError(f"unexpected compiler version text for {path}")
    return value


def _read_dpkg_versions(image: str) -> list[dict[str, str]]:
    result = _run_in_image(image, ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"])
    text = _text(result.stdout, "dpkg-query stdout")
    lines = text.splitlines()
    if not lines or any(not line for line in lines):
        raise BuildLockError("dpkg-query output was empty or contained a blank record")
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0] or not fields[1] or any("\n" in field for field in fields):
            raise BuildLockError("dpkg-query output contained a malformed record")
        package, version = fields
        if package in seen:
            raise BuildLockError("dpkg-query output contained a duplicate package")
        seen.add(package)
        records.append({"package": package, "version": version})
    return sorted(records, key=lambda record: (record["package"], record["version"]))


def _read_cmake_cache(image: str) -> tuple[str, list[dict[str, str]]]:
    result = _run_in_image(image, ["cat", CMAKE_CACHE_PATH])
    raw = _as_bytes(result.stdout, "CMake cache stdout")
    digest = hashlib.sha256(raw).hexdigest()
    text = _text(raw, "CMake cache")
    relevant: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line or line.startswith("//") or line.startswith("#"):
            continue
        match = _CACHE_ENTRY_RE.fullmatch(line)
        if match is None:
            raise BuildLockError("CMake cache contained a malformed entry")
        key = match.group("key")
        upper_key = key.upper()
        if (
            "LLVM" in upper_key
            or "CLANG" in upper_key
            or key in {"CMAKE_BUILD_TYPE", "CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER", "CMAKE_INSTALL_PREFIX"}
        ):
            relevant.append(
                {
                    "key": key,
                    "raw": line,
                    "type": match.group("type"),
                    "value": match.group("value"),
                }
            )
    return digest, sorted(relevant, key=lambda entry: entry["raw"])


def _dockerfile_record(path: Path) -> tuple[str, str]:
    descriptor = -1
    try:
        if path.is_symlink() or not path.is_file():
            raise BuildLockError("--dockerfile must name a regular file")
        resolved = path.resolve(strict=True)
        before = os.stat(resolved, follow_symlinks=False)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(resolved, flags)
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if not stat.S_ISREG(opened.st_mode) or identity != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise BuildLockError("--dockerfile changed before hashing")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        after = os.fstat(descriptor)
        closing_path = os.stat(resolved, follow_symlinks=False)
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or identity != (
            closing_path.st_dev,
            closing_path.st_ino,
            closing_path.st_mode,
            closing_path.st_size,
            closing_path.st_mtime_ns,
            closing_path.st_ctime_ns,
        ):
            raise BuildLockError("--dockerfile changed during hashing")
        return str(resolved), digest.hexdigest()
    except OSError as exc:
        raise BuildLockError("could not read --dockerfile") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def collect_build_lock(image: str, dockerfile: Path) -> dict[str, Any]:
    if not image:
        raise BuildLockError("--image must not be empty")
    dockerfile_path, dockerfile_sha256 = _dockerfile_record(dockerfile)
    metadata = _inspect_image(image)
    image_record = _validate_image_metadata(image, metadata)
    immutable_image = image_record["id"]
    image_record["measurement_reference"] = immutable_image
    architecture = _validate_container_architecture(immutable_image)
    cmake_sha256, cmake_entries = _read_cmake_cache(immutable_image)
    result = {
        "authority": dict(AUTHORITY_BITS),
        "dockerfile": {
            "path": dockerfile_path,
            "sha256": dockerfile_sha256,
        },
        "image": image_record,
        "schema": SCHEMA,
        "toolchain": {
            "architecture": architecture,
            "cmake": {
                "cache_sha256": cmake_sha256,
                "relevant_entries": cmake_entries,
            },
            "compilers": {
                "clang": {
                    "path": CLANG_PATH,
                    "sha256": _sha256sum_in_image(immutable_image, CLANG_PATH),
                    "version": _version_in_image(immutable_image, CLANG_PATH),
                },
                "clang++": {
                    "path": CLANGXX_PATH,
                    "sha256": _sha256sum_in_image(immutable_image, CLANGXX_PATH),
                    "version": _version_in_image(immutable_image, CLANGXX_PATH),
                },
            },
            "llvm": {
                "commit": LLVM_COMMIT,
                "source_sha256": LLVM_SOURCE_SHA256,
                "tag": LLVM_TAG,
            },
            "dpkg_packages": _read_dpkg_versions(immutable_image),
        },
    }
    closing_metadata = _inspect_image(image)
    if closing_metadata.get("Id") != immutable_image:
        raise BuildLockError("Docker image reference changed during collection")
    return result


def _compact_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _write_output(path: Path, payload: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    except OSError as exc:
        raise BuildLockError("could not write --output") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--dockerfile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        payload = collect_build_lock(args.image, args.dockerfile)
        _write_output(args.output, _compact_json(payload))
    except BuildLockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
