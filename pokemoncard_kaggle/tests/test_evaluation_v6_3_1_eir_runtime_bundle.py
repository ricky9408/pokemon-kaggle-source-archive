import os
import stat
from pathlib import Path

import pytest

import evaluation_v6_3_1.eir_runtime_bundle as runtime_bundle
from evaluation_v6_3_1.eir_prebinding import EIRPrebindingError
from evaluation_v6_3_1.eir_runtime_bundle import (
    RUNTIME_BUNDLE_ENTRYPOINT_NOT_EXECUTABLE,
    RUNTIME_BUNDLE_ENTRYPOINT_SHEBANG,
    RUNTIME_BUNDLE_ENTRYPOINT_DIGEST_DRIFT,
    RUNTIME_BUNDLE_ENTRYPOINT_SIZE_DRIFT,
    RUNTIME_BUNDLE_FILE_DIGEST_DRIFT,
    RUNTIME_BUNDLE_FILE_SIZE_DRIFT,
    RUNTIME_BUNDLE_MISSING_OBJECT,
    RUNTIME_BUNDLE_PERMISSION_DRIFT,
    RUNTIME_BUNDLE_RACE_DETECTED,
    RUNTIME_BUNDLE_SPECIAL_INODE,
    RUNTIME_BUNDLE_SYMLINK_CYCLE,
    RUNTIME_BUNDLE_SYMLINK_ESCAPE,
    RUNTIME_BUNDLE_SYMLINK_TARGET_DRIFT,
    RUNTIME_BUNDLE_UNMANIFESTED_OBJECT,
    RUNTIME_RESERVED_PATH_COLLISION,
    SCRIPT_ENTRYPOINT_FORBIDDEN,
    RuntimeBundleLimits,
    assert_toolchain_runtime_bundle,
    build_toolchain_runtime_manifest,
    verify_toolchain_runtime_bundle,
)


PLATFORM = ["linux-gnu", "amd64", 1, 64, 8]


def _write_executable(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o755)


def _base_root(tmp_path: Path) -> tuple[Path, list[object]]:
    root = tmp_path / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    _write_executable(root / "bin/compiler", b"compiler-bytes\x00")
    _write_executable(root / "bin/extractor", b"extractor-bytes\x00")
    (root / "lib/data").write_bytes(b"runtime-data")
    manifest = build_toolchain_runtime_manifest(
        root,
        compiler_entry_path="/bin/compiler",
        extractor_entry_path="/bin/extractor",
        runtime_platform=PLATFORM,
    )
    return root, manifest


def _codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


def test_build_and_verify_exact_rootfs_is_byte_only(tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    report = verify_toolchain_runtime_bundle(root, manifest)

    assert report.verified
    assert report.runtime_root is not None
    assert report.state == "RUNTIME_BUNDLE_BYTES_ONLY"
    assert not report.compiler_recomputed
    assert not report.external_evidence_valid
    assert not report.authority
    assert not report.engine_wiring_authority
    assert not report.upload_authority
    assert not report.permit_authority
    assert not report.holdout_access_authority
    assert not report.agent_modification_authority
    assert report.manifest == manifest
    assert any("atomic snapshot" in limitation for limitation in report.limitations)

    checked = assert_toolchain_runtime_bundle(root, manifest)
    assert checked.runtime_root == report.runtime_root


def test_fd_verifier_retains_caller_descriptor(tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        report = runtime_bundle.assert_toolchain_runtime_bundle_fd(root_fd, manifest)
        assert report.verified
        assert stat.S_ISDIR(os.fstat(root_fd).st_mode)
    finally:
        os.close(root_fd)


def test_unmanifested_and_missing_objects_are_distinct(tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    (root / "lib/new-file").write_bytes(b"new")
    report = verify_toolchain_runtime_bundle(root, manifest)
    assert RUNTIME_BUNDLE_UNMANIFESTED_OBJECT in _codes(report)

    (root / "lib/new-file").unlink()
    (root / "lib/data").unlink()
    report = verify_toolchain_runtime_bundle(root, manifest)
    assert RUNTIME_BUNDLE_MISSING_OBJECT in _codes(report)


def test_regular_file_size_and_digest_drift_are_detected(tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    (root / "lib/data").write_bytes(b"changed-runtime-data")
    report = verify_toolchain_runtime_bundle(root, manifest)
    codes = _codes(report)
    assert RUNTIME_BUNDLE_FILE_SIZE_DRIFT in codes
    assert RUNTIME_BUNDLE_FILE_DIGEST_DRIFT in codes


def test_entrypoint_size_and_digest_drift_have_entrypoint_codes(tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    (root / "bin/compiler").write_bytes(b"changed-compiler-bytes")
    report = verify_toolchain_runtime_bundle(root, manifest)
    codes = _codes(report)
    assert RUNTIME_BUNDLE_ENTRYPOINT_SIZE_DRIFT in codes
    assert RUNTIME_BUNDLE_ENTRYPOINT_DIGEST_DRIFT in codes


def test_directory_permission_drift_is_detected(tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    directory = root / "lib"
    original = stat.S_IMODE(directory.stat().st_mode)
    try:
        directory.chmod(original ^ stat.S_IWUSR)
        report = verify_toolchain_runtime_bundle(root, manifest)
        assert RUNTIME_BUNDLE_PERMISSION_DRIFT in _codes(report)
    finally:
        directory.chmod(original)


def test_symlink_target_drift_is_detected(tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    os.symlink("../bin/compiler", root / "lib/tool")
    manifest = build_toolchain_runtime_manifest(
        root,
        compiler_entry_path="/bin/compiler",
        extractor_entry_path="/bin/extractor",
        runtime_platform=PLATFORM,
    )
    (root / "lib/tool").unlink()
    os.symlink("../bin/extractor", root / "lib/tool")
    report = verify_toolchain_runtime_bundle(root, manifest)
    assert RUNTIME_BUNDLE_SYMLINK_TARGET_DRIFT in _codes(report)


def test_symlink_escape_and_cycle_fail_closed_during_build(tmp_path: Path) -> None:
    root, _ = _base_root(tmp_path)
    os.symlink("../../outside", root / "lib/escape")
    with pytest.raises(EIRPrebindingError) as escaped:
        build_toolchain_runtime_manifest(
            root,
            compiler_entry_path="/bin/compiler",
            extractor_entry_path="/bin/extractor",
            runtime_platform=PLATFORM,
        )
    assert escaped.value.code == RUNTIME_BUNDLE_SYMLINK_ESCAPE

    (root / "lib/escape").unlink()
    os.symlink("cycle-b", root / "lib/cycle-a")
    os.symlink("cycle-a", root / "lib/cycle-b")
    with pytest.raises(EIRPrebindingError) as cycled:
        build_toolchain_runtime_manifest(
            root,
            compiler_entry_path="/bin/compiler",
            extractor_entry_path="/bin/extractor",
            runtime_platform=PLATFORM,
        )
    assert cycled.value.code == RUNTIME_BUNDLE_SYMLINK_CYCLE


def test_special_inode_is_rejected(tmp_path: Path) -> None:
    root, _ = _base_root(tmp_path)
    fifo = root / "lib/pipe"
    try:
        os.mkfifo(fifo)
    except (AttributeError, NotImplementedError, OSError):
        pytest.skip("named pipes are unavailable on this filesystem")
    with pytest.raises(EIRPrebindingError) as raised:
        build_toolchain_runtime_manifest(
            root,
            compiler_entry_path="/bin/compiler",
            extractor_entry_path="/bin/extractor",
            runtime_platform=PLATFORM,
        )
    assert raised.value.code == RUNTIME_BUNDLE_SPECIAL_INODE


def test_entrypoint_must_be_executable_and_not_a_script(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    (root / "bin").mkdir(parents=True)
    compiler = root / "bin/compiler"
    extractor = root / "bin/extractor"
    compiler.write_bytes(b"#!/bin/sh\nexit 0\n")
    extractor.write_bytes(b"native-extractor")
    compiler.chmod(0o755)
    extractor.chmod(0o755)
    with pytest.raises(EIRPrebindingError) as shebang:
        build_toolchain_runtime_manifest(
            root,
            compiler_entry_path="/bin/compiler",
            extractor_entry_path="/bin/extractor",
            runtime_platform=PLATFORM,
        )
    assert shebang.value.code == RUNTIME_BUNDLE_ENTRYPOINT_SHEBANG
    assert shebang.value.code == SCRIPT_ENTRYPOINT_FORBIDDEN

    compiler.write_bytes(b"native-compiler")
    compiler.chmod(0o644)
    with pytest.raises(EIRPrebindingError) as executable:
        build_toolchain_runtime_manifest(
            root,
            compiler_entry_path="/bin/compiler",
            extractor_entry_path="/bin/extractor",
            runtime_platform=PLATFORM,
        )
    assert executable.value.code == RUNTIME_BUNDLE_ENTRYPOINT_NOT_EXECUTABLE


def test_entrypoint_symlink_resolves_inside_bundle(tmp_path: Path) -> None:
    root, _ = _base_root(tmp_path)
    (root / "bin/compiler").rename(root / "bin/compiler-real")
    os.symlink("compiler-real", root / "bin/compiler")
    manifest = build_toolchain_runtime_manifest(
        root,
        compiler_entry_path="/bin/compiler",
        extractor_entry_path="/bin/extractor",
        runtime_platform=PLATFORM,
    )
    report = verify_toolchain_runtime_bundle(root, manifest)
    assert report.verified


def test_race_is_reported_when_a_regular_file_changes_during_open(monkeypatch, tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    original_fstat = os.fstat
    calls = {"count": 0}

    def changing_fstat(fd):
        result = original_fstat(fd)
        calls["count"] += 1
        if calls["count"] == 1:
            values = list(result)
            values[stat.ST_SIZE] += 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(os, "fstat", changing_fstat)
    report = verify_toolchain_runtime_bundle(root, manifest)
    assert RUNTIME_BUNDLE_RACE_DETECTED in _codes(report)


def test_limits_bound_file_reads_and_entry_count(tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    report = verify_toolchain_runtime_bundle(
        root,
        manifest,
        limits=RuntimeBundleLimits(max_file_bytes=4, max_total_file_bytes=8),
    )
    assert "RUNTIME_BUNDLE_LIMIT_EXCEEDED" in _codes(report)


@pytest.mark.parametrize(
    "reserved",
    [
        "dev",
        "proc",
        "sys",
        "v631302/input",
        "v631302/src",
        "v631302/work",
    ],
)
def test_reserved_state3_runtime_namespaces_are_rejected(tmp_path: Path, reserved: str) -> None:
    root, manifest = _base_root(tmp_path)
    reserved_path = root / reserved
    reserved_path.mkdir(parents=True)

    with pytest.raises(EIRPrebindingError) as built:
        build_toolchain_runtime_manifest(
            root,
            compiler_entry_path="/bin/compiler",
            extractor_entry_path="/bin/extractor",
            runtime_platform=PLATFORM,
        )
    assert built.value.code == RUNTIME_RESERVED_PATH_COLLISION

    injected = [manifest[0], manifest[1], manifest[2], list(manifest[3]), [list(item) for item in manifest[4]]]
    injected_entries = injected[4]
    virtual = "/" + reserved
    injected_entries.append([virtual, 2, 0o755, 0, b"\x00" * 32, ""])
    injected[4] = sorted(injected_entries, key=lambda item: item[0].encode("utf-8"))
    report = verify_toolchain_runtime_bundle(root, injected)
    assert RUNTIME_RESERVED_PATH_COLLISION in _codes(report)


def test_runtime_symlink_cannot_enter_reserved_namespace(tmp_path: Path) -> None:
    root, _ = _base_root(tmp_path)
    os.symlink("/dev/null", root / "lib/device")
    with pytest.raises(EIRPrebindingError) as raised:
        build_toolchain_runtime_manifest(
            root,
            compiler_entry_path="/bin/compiler",
            extractor_entry_path="/bin/extractor",
            runtime_platform=PLATFORM,
        )
    assert raised.value.code == RUNTIME_BUNDLE_SYMLINK_ESCAPE


def test_parent_directory_replacement_cannot_escape_rootfs(monkeypatch, tmp_path: Path) -> None:
    root, _ = _base_root(tmp_path)
    nested = root / "nested"
    nested.mkdir()
    (nested / "payload").write_bytes(b"inside")
    manifest = build_toolchain_runtime_manifest(
        root,
        compiler_entry_path="/bin/compiler",
        extractor_entry_path="/bin/extractor",
        runtime_platform=PLATFORM,
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_bytes(b"outside")

    original_open = os.open
    nested_opens = {"count": 0}

    def replacing_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == "nested" and dir_fd is not None:
            nested_opens["count"] += 1
            if nested_opens["count"] == 2:
                nested.rename(root / "nested-old")
                os.symlink(outside, nested)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", replacing_open)
    report = verify_toolchain_runtime_bundle(root, manifest)
    assert RUNTIME_BUNDLE_RACE_DETECTED in _codes(report)


def test_entry_limit_is_enforced_while_directory_is_enumerated(tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    report = verify_toolchain_runtime_bundle(
        root,
        manifest,
        limits=RuntimeBundleLimits(max_entries=5),
    )
    assert "RUNTIME_BUNDLE_LIMIT_EXCEEDED" in _codes(report)


def test_entrypoints_are_not_reread_outside_the_bundle_budget(monkeypatch, tmp_path: Path) -> None:
    root, manifest = _base_root(tmp_path)
    original_open = os.open
    regular_opens = {"compiler": 0, "extractor": 0}

    def counting_open(path, flags, mode=0o777, *, dir_fd=None):
        if path in regular_opens and not flags & getattr(os, "O_DIRECTORY", 0):
            regular_opens[path] += 1
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", counting_open)
    report = verify_toolchain_runtime_bundle(root, manifest)
    assert report.verified
    assert regular_opens == {"compiler": 1, "extractor": 1}


def test_growth_is_stopped_at_the_verification_wide_byte_budget(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    payload = root / "payload"
    payload.write_bytes(b"ab")
    parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    initial = os.stat("payload", dir_fd=parent_fd, follow_symlinks=False)
    original_read = os.read
    injected = {"done": False}

    def growing_read(fd, count):
        chunk = original_read(fd, count)
        if not chunk and not injected["done"]:
            injected["done"] = True
            return b"x"
        return chunk

    monkeypatch.setattr(os, "read", growing_read)
    try:
        with pytest.raises(EIRPrebindingError) as raised:
            runtime_bundle._safe_regular_bytes_at(
                parent_fd,
                "payload",
                "/payload",
                initial,
                RuntimeBundleLimits(
                    max_file_bytes=3,
                    max_total_file_bytes=3,
                    read_chunk_bytes=2,
                ),
                [1],
            )
    finally:
        os.close(parent_fd)
    assert raised.value.code == "RUNTIME_BUNDLE_LIMIT_EXCEEDED"
