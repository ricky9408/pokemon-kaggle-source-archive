from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import evaluation_v5.openssl_runtime as module


def test_resolved_executable_is_hashed_and_authority_free(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / "openssl-real"
    executable.write_bytes(b"trusted-openssl\n")
    monkeypatch.setattr(module.shutil, "which", lambda _name: str(executable))
    monkeypatch.setattr(module, "_assert_system_immutable_path", lambda _path: None)
    result = module.resolve_and_hash_openssl()
    assert result["path"] == str(executable.resolve())
    assert result["sha256"] == hashlib.sha256(executable.read_bytes()).hexdigest()
    assert result["authority"] is False
    assert result["submission_authorized"] is False
    assert result["holdout_access_authorized"] is False


def test_pinned_hash_mismatch_fails_closed(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / "openssl-real"
    executable.write_bytes(b"unexpected\n")
    monkeypatch.setattr(module.shutil, "which", lambda _name: str(executable))
    monkeypatch.setattr(module, "_assert_system_immutable_path", lambda _path: None)
    with pytest.raises(module.OpenSSLRuntimeError, match="does not match"):
        module.verify_pinned_openssl("0" * 64)


@pytest.mark.parametrize("name", ["", "./openssl", "bin/openssl", "/usr/bin/openssl"])
def test_only_bare_lookup_names_are_accepted(name: str) -> None:
    with pytest.raises(module.OpenSSLRuntimeError):
        module.resolve_and_hash_openssl(name)


def test_writable_or_nonroot_path_is_rejected(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / "openssl-real"
    executable.write_bytes(b"user-controlled\n")
    monkeypatch.setattr(module.shutil, "which", lambda _name: str(executable))
    with pytest.raises(module.OpenSSLRuntimeError, match="root-owned"):
        module.resolve_and_hash_openssl()
