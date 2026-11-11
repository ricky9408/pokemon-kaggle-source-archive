"""Descriptor-bound identity checks for the RFC 3161 OpenSSL verifier.

The timestamp CA and policy are insufficient if an attacker can replace the
``openssl`` executable selected through ``PATH``.  This module resolves that
executable once, hashes the opened regular file without following the resolved
leaf, and returns the absolute path whose bytes matched an implementation-pinned
trust root.  It grants no evaluation or submission authority.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class OpenSSLRuntimeError(ValueError):
    """The timestamp verifier executable is absent, mutable, or untrusted."""


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _assert_system_immutable_path(path: Path) -> None:
    """Require the executable and every parent to be root-owned and non-writable."""

    current = path
    while True:
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError as exc:
            raise OpenSSLRuntimeError("OpenSSL path cannot be audited") from exc
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise OpenSSLRuntimeError(
                "OpenSSL executable path is not root-owned and non-writable"
            )
        if current.parent == current:
            break
        current = current.parent


def resolve_and_hash_openssl(openssl_bin: str = "openssl") -> dict[str, Any]:
    """Resolve and securely hash one OpenSSL executable selected by name."""

    if type(openssl_bin) is not str or not openssl_bin or Path(openssl_bin).name != openssl_bin:
        raise OpenSSLRuntimeError("openssl_bin must be one bare executable name")
    selected = shutil.which(openssl_bin)
    if selected is None:
        raise OpenSSLRuntimeError("OpenSSL executable is unavailable")
    try:
        resolved = Path(selected).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise OpenSSLRuntimeError("OpenSSL executable cannot be resolved") from exc
    _assert_system_immutable_path(resolved)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise OpenSSLRuntimeError("OpenSSL executable cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OpenSSLRuntimeError("OpenSSL executable is not a regular file")
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
        raise OpenSSLRuntimeError("OpenSSL executable cannot be read safely") from exc
    finally:
        os.close(descriptor)
    if total != before.st_size or _file_identity(before) != _file_identity(after):
        raise OpenSSLRuntimeError("OpenSSL executable changed while it was hashed")
    _assert_system_immutable_path(resolved)
    return {
        "authority": False,
        "path": str(resolved),
        "sha256": digest.hexdigest(),
        "submission_authorized": False,
        "holdout_access_authorized": False,
    }


def verify_pinned_openssl(expected_sha256: str, openssl_bin: str = "openssl") -> str:
    """Return the absolute executable path only when its bytes match the pin."""

    if type(expected_sha256) is not str or _SHA256_RE.fullmatch(expected_sha256) is None:
        raise OpenSSLRuntimeError("expected OpenSSL SHA-256 is not configured")
    identity = resolve_and_hash_openssl(openssl_bin)
    if identity["sha256"] != expected_sha256:
        raise OpenSSLRuntimeError("OpenSSL executable SHA-256 does not match the trust root")
    return identity["path"]


__all__ = [
    "OpenSSLRuntimeError",
    "resolve_and_hash_openssl",
    "verify_pinned_openssl",
]
