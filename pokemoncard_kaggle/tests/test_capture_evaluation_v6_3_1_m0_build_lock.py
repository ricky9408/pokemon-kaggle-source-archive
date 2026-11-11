from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from tools.capture_evaluation_v6_3_1_m0_build_lock import (
    BuildLockError,
    CMAKE_CACHE_PATH,
    CLANGXX_PATH,
    CLANG_PATH,
    LLVM_COMMIT,
    LLVM_SOURCE_SHA256,
    LLVM_TAG,
    PROTOCOL,
    SCHEMA,
    collect_build_lock,
    main,
)


IMAGE = "pokemon-v631302-clang16-dev:20260802"
CLANG_SHA = "11" * 32
CLANGXX_SHA = "22" * 32
IMAGE_ID = "sha256:" + ("33" * 32)
REPO_DIGEST = "docker.io/example/m0@sha256:" + ("44" * 32)
CMAKE_CACHE = b"""# This is the CMakeCache file.\nCMAKE_BUILD_TYPE:STRING=Release\nCMAKE_C_COMPILER:FILEPATH=/usr/bin/clang-16\nCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/clang++-16\nLLVM_ENABLE_PROJECTS:STRING=clang\nLLVM_TARGETS_TO_BUILD:STRING=X86\nUNRELATED:STRING=ignored\n"""
DPKG = b"zlib1g:amd64\t1.2.13\nclang-16\t1:16.0.6\n"


def _image_metadata(
    *,
    architecture: str = "amd64",
    labels: dict[str, str] | None = None,
    image_id: str = IMAGE_ID,
) -> bytes:
    labels = labels or {
        "io.garlictoday.evaluation.protocol": PROTOCOL,
        "io.garlictoday.evaluation.authority": "false",
        "io.garlictoday.evaluation.llvm-tag": LLVM_TAG,
        "io.garlictoday.evaluation.llvm-commit": LLVM_COMMIT,
        "io.garlictoday.evaluation.llvm-source-sha256": LLVM_SOURCE_SHA256,
    }
    return json.dumps(
        [
            {
                "Architecture": architecture,
                "Config": {"Labels": labels},
                "Id": image_id,
                "Os": "linux",
                "RepoDigests": [REPO_DIGEST],
            }
        ]
    ).encode()


def _runner(*, image_stdout: bytes | None = None, command_overrides: dict[tuple[str, ...], tuple[int, bytes, bytes]] | None = None):
    image_stdout = image_stdout or _image_metadata()
    overrides = command_overrides or {}

    def run(command, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["capture_output"] is True
        key = tuple(command)
        if key[:4] == ("docker", "image", "inspect", IMAGE):
            return subprocess.CompletedProcess(command, 0, image_stdout, b"")
        if key in overrides:
            return subprocess.CompletedProcess(command, *overrides[key])
        if key[-2:] == ("uname", "-s"):
            return subprocess.CompletedProcess(command, 0, b"Linux\n", b"")
        if key[-2:] == ("uname", "-m"):
            return subprocess.CompletedProcess(command, 0, b"x86_64\n", b"")
        if key[-2:] == ("dpkg", "--print-architecture"):
            return subprocess.CompletedProcess(command, 0, b"amd64\n", b"")
        if key[-2:] == (key[-2], "--version"):
            path = key[-3]
            return subprocess.CompletedProcess(command, 0, f"{path} clang version 16.0.6\n".encode(), b"")
        if key[-2:] == ("sha256sum", CLANG_PATH):
            return subprocess.CompletedProcess(command, 0, f"{CLANG_SHA}  {CLANG_PATH}\n".encode(), b"")
        if key[-2:] == ("sha256sum", CLANGXX_PATH):
            return subprocess.CompletedProcess(command, 0, f"{CLANGXX_SHA}  {CLANGXX_PATH}\n".encode(), b"")
        if key[-3:] == ("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"):
            return subprocess.CompletedProcess(command, 0, DPKG, b"")
        if key[-2:] == ("cat", "/opt/llvm-build/CMakeCache.txt"):
            return subprocess.CompletedProcess(command, 0, CMAKE_CACHE, b"")
        raise AssertionError(f"unexpected command: {command!r}")

    return run


def _dockerfile(tmp_path: Path) -> Path:
    path = tmp_path / "Dockerfile.dev"
    path.write_bytes(b"FROM debian:bookworm-slim\n")
    return path


def test_success_collects_lock_and_all_authority_bits_are_false(tmp_path: Path) -> None:
    with patch("tools.capture_evaluation_v6_3_1_m0_build_lock.subprocess.run", side_effect=_runner()):
        payload = collect_build_lock(IMAGE, _dockerfile(tmp_path))

    assert payload["schema"] == SCHEMA
    assert payload["image"]["architecture"] == "amd64"
    assert payload["image"]["measurement_reference"] == IMAGE_ID
    assert payload["image"]["repo_digests"] == [REPO_DIGEST]
    assert payload["toolchain"]["llvm"] == {
        "commit": LLVM_COMMIT,
        "source_sha256": LLVM_SOURCE_SHA256,
        "tag": LLVM_TAG,
    }
    assert payload["toolchain"]["compilers"]["clang"]["sha256"] == CLANG_SHA
    assert payload["toolchain"]["cmake"]["cache_sha256"] == hashlib.sha256(CMAKE_CACHE).hexdigest()
    assert [row["package"] for row in payload["toolchain"]["dpkg_packages"]] == ["clang-16", "zlib1g:amd64"]
    assert payload["authority"]
    assert all(value is False for value in payload["authority"].values())


def test_wrong_architecture_fails_closed(tmp_path: Path) -> None:
    with patch(
        "tools.capture_evaluation_v6_3_1_m0_build_lock.subprocess.run",
        side_effect=_runner(image_stdout=_image_metadata(architecture="arm64")),
    ):
        with pytest.raises(BuildLockError, match="linux/amd64"):
            collect_build_lock(IMAGE, _dockerfile(tmp_path))


def test_wrong_label_fails_closed(tmp_path: Path) -> None:
    labels = {
        "io.garlictoday.evaluation.protocol": PROTOCOL,
        "io.garlictoday.evaluation.authority": "true",
        "io.garlictoday.evaluation.llvm-tag": LLVM_TAG,
        "io.garlictoday.evaluation.llvm-commit": LLVM_COMMIT,
        "io.garlictoday.evaluation.llvm-source-sha256": LLVM_SOURCE_SHA256,
    }
    with patch(
        "tools.capture_evaluation_v6_3_1_m0_build_lock.subprocess.run",
        side_effect=_runner(image_stdout=_image_metadata(labels=labels)),
    ):
        with pytest.raises(BuildLockError, match="label mismatch"):
            collect_build_lock(IMAGE, _dockerfile(tmp_path))


def test_malformed_binary_hash_fails_closed(tmp_path: Path) -> None:
    bad = ("not-a-hash" + "0" * 54).encode() + f"  {CLANG_PATH}\n".encode()
    key = ("docker", "run", "--rm", "--platform", "linux/amd64", IMAGE_ID, "sha256sum", CLANG_PATH)
    with patch(
        "tools.capture_evaluation_v6_3_1_m0_build_lock.subprocess.run",
        side_effect=_runner(command_overrides={key: (0, bad, b"")}),
    ):
        with pytest.raises(BuildLockError, match="sha256sum output mismatch"):
            collect_build_lock(IMAGE, _dockerfile(tmp_path))


def test_main_output_is_deterministic_and_compact(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path)
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    with patch("tools.capture_evaluation_v6_3_1_m0_build_lock.subprocess.run", side_effect=_runner()):
        assert main(["--image", IMAGE, "--dockerfile", str(dockerfile), "--output", str(first)]) == 0
    with patch("tools.capture_evaluation_v6_3_1_m0_build_lock.subprocess.run", side_effect=_runner()):
        assert main(["--image", IMAGE, "--dockerfile", str(dockerfile), "--output", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes().endswith(b"\n")
    assert b"\n  " not in first.read_bytes()
    assert json.loads(first.read_text()) ["schema"] == SCHEMA


def test_real_cmake_cache_key_with_hyphen_is_accepted(tmp_path: Path) -> None:
    cache = CMAKE_CACHE + b"CLANG_TOOL_CLANG_FORMAT_BUILD-ADVANCED:INTERNAL=1\n"
    key = ("docker", "run", "--rm", "--platform", "linux/amd64", IMAGE_ID, "cat", CMAKE_CACHE_PATH)
    with patch(
        "tools.capture_evaluation_v6_3_1_m0_build_lock.subprocess.run",
        side_effect=_runner(command_overrides={key: (0, cache, b"")}),
    ):
        payload = collect_build_lock(IMAGE, _dockerfile(tmp_path))

    assert any(
        row["key"] == "CLANG_TOOL_CLANG_FORMAT_BUILD-ADVANCED"
        for row in payload["toolchain"]["cmake"]["relevant_entries"]
    )


def test_image_retag_during_collection_fails_closed(tmp_path: Path) -> None:
    replacement_id = "sha256:" + ("55" * 32)
    base = _runner()
    inspect_count = 0

    def retagging_runner(command, **kwargs):
        nonlocal inspect_count
        if tuple(command[:4]) == ("docker", "image", "inspect", IMAGE):
            inspect_count += 1
            payload = _image_metadata(
                image_id=IMAGE_ID if inspect_count == 1 else replacement_id
            )
            return subprocess.CompletedProcess(command, 0, payload, b"")
        return base(command, **kwargs)

    with patch(
        "tools.capture_evaluation_v6_3_1_m0_build_lock.subprocess.run",
        side_effect=retagging_runner,
    ):
        with pytest.raises(BuildLockError, match="changed during collection"):
            collect_build_lock(IMAGE, _dockerfile(tmp_path))


def test_dockerfile_mutation_during_hash_fails_closed(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path)
    real_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor: int):
        nonlocal calls
        result = real_fstat(descriptor)
        calls += 1
        if calls == 2:
            values = list(result)
            values[6] = result.st_size + 1
            return os.stat_result(values)
        return result

    with patch(
        "tools.capture_evaluation_v6_3_1_m0_build_lock.os.fstat",
        side_effect=changing_fstat,
    ):
        with pytest.raises(BuildLockError, match="changed during hashing"):
            collect_build_lock(IMAGE, dockerfile)
