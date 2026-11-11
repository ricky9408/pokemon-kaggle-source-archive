#!/usr/bin/env python3
"""Read-only v6.2.3 recruitment helpers.

This command line interface handles public evidence only.  It never reads a
private key, creates a permit or preregistration root, accesses a holdout, or
authorizes an upload.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Mapping
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from evaluation_v6_2.attestation_v623 import (
    DOMAIN_CONTRIBUTOR,
    DOMAIN_LINEAGE,
    DOMAIN_POPULATION,
    DOMAIN_REGISTRY,
    DOMAIN_REVOCATION,
    DOMAIN_TECHNICAL,
    PinnedRegistryAdmin,
    assess_population_trust_file,
    signing_message,
)
from evaluation_v6_2.integration_v622 import canonical_json_bytes, canonical_json_loads


CLI_SCHEMA = "eval.v6.2.3.recruitment-cli-result"
PINNED_ADMINS_SCHEMA = "eval.v6.2.3.pinned-registry-admins"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_INPUT_BYTES = 64 * 1024 * 1024

_ARTIFACT_DOMAINS = {
    "registry": DOMAIN_REGISTRY,
    "revocation": DOMAIN_REVOCATION,
    "contributor": DOMAIN_CONTRIBUTOR,
    "technical": DOMAIN_TECHNICAL,
    "lineage": DOMAIN_LINEAGE,
    "population": DOMAIN_POPULATION,
}


class RecruitmentCliError(ValueError):
    """An invalid or unsafe recruitment CLI input."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RecruitmentCliError(message)


def _read_regular_file(path: str | os.PathLike[str], *, label: str) -> bytes:
    """Read one bounded regular file without following its final symlink."""

    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise RecruitmentCliError(f"unable to open {label} safely: {exc}") from exc

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RecruitmentCliError(f"{label} must be a regular file")
        if before.st_size <= 0 or before.st_size > _MAX_INPUT_BYTES:
            raise RecruitmentCliError(f"{label} size is empty or exceeds the 64 MiB limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise RecruitmentCliError(f"{label} was truncated during the read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RecruitmentCliError(f"{label} grew during the read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise RecruitmentCliError(f"{label} changed during the read")
    return b"".join(chunks)


def _read_canonical_json(path: str | os.PathLike[str], *, label: str) -> tuple[Mapping[str, Any], bytes]:
    raw = _read_regular_file(path, label=label)
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or raw.endswith(b"\n"):
        raise RecruitmentCliError(f"{label} must use exact UTF-8 canonical JSON framing")
    try:
        value = canonical_json_loads(raw)
        encoded = canonical_json_bytes(value)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise RecruitmentCliError(f"{label} is not valid canonical JSON: {exc}") from exc
    if type(value) is not dict or raw != encoded:
        raise RecruitmentCliError(f"{label} bytes are not canonical JSON")
    return value, raw


def _public_key_from_bytes(raw: bytes, *, label: str) -> bytes:
    if len(raw) == 32:
        public_key = raw
    else:
        try:
            loaded = serialization.load_pem_public_key(raw)
        except (TypeError, ValueError) as exc:
            raise RecruitmentCliError(f"{label} must be raw 32-byte or PEM Ed25519 public key") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise RecruitmentCliError(f"{label} PEM key is not Ed25519")
        try:
            public_key = loaded.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except ValueError as exc:
            raise RecruitmentCliError(f"{label} PEM key cannot be encoded as raw Ed25519") from exc
    try:
        # The attestation module applies the repository's strict Ed25519 key
        # validation, including the key-id derivation contract.
        _derived_key_id(public_key)
    except (AttributeError, ValueError) as exc:
        raise RecruitmentCliError(f"{label} is not a strict Ed25519 public key") from exc
    return public_key


def _derived_key_id(public_key: bytes) -> str:
    return PinnedRegistryAdmin(
        entity_id="recruitment-cli",
        public_key=public_key,
        external_identity_receipt_sha256="0" * 64,
    ).key_id


def _key_id_from_file(path: str | os.PathLike[str]) -> str:
    return _derived_key_id(
        _public_key_from_bytes(
            _read_regular_file(path, label="public key"), label="public key"
        )
    )


def _sha256_argument(value: str, *, label: str) -> str:
    if _SHA256_RE.fullmatch(value) is None:
        raise RecruitmentCliError(f"{label} must be lowercase SHA-256 hex")
    return value


def _pinned_admins(path: str | os.PathLike[str], expected_sha256: str) -> dict[str, PinnedRegistryAdmin]:
    config, raw = _read_canonical_json(path, label="pinned-admin config")
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    expected = _sha256_argument(expected_sha256, label="--pinned-admins-sha256")
    if not hmac.compare_digest(actual_sha256, expected):
        raise RecruitmentCliError("--pinned-admins-sha256 does not match exact config bytes")

    if set(config) != {"schema", "admins"} or config["schema"] != PINNED_ADMINS_SCHEMA:
        raise RecruitmentCliError(f"pinned-admin config schema must be {PINNED_ADMINS_SCHEMA}")
    admins = config["admins"]
    if type(admins) is not list or len(admins) != 3:
        raise RecruitmentCliError("pinned-admin config must contain exactly three admins")

    result: dict[str, PinnedRegistryAdmin] = {}
    entities: set[str] = set()
    public_keys: set[bytes] = set()
    for index, record in enumerate(admins):
        if type(record) is not dict or set(record) != {
            "entity_id",
            "public_key_ed25519_base64",
            "external_identity_receipt_sha256",
        }:
            raise RecruitmentCliError(
                f"pinned admin {index} fields are invalid"
            )
        entity_id = record["entity_id"]
        if type(entity_id) is not str or not entity_id or entity_id.strip() != entity_id or "\0" in entity_id:
            raise RecruitmentCliError(f"pinned admin {index} entity_id is invalid")
        encoded_key = record["public_key_ed25519_base64"]
        if type(encoded_key) is not str:
            raise RecruitmentCliError(f"pinned admin {index} public key must be canonical base64")
        try:
            public_key = base64.b64decode(encoded_key, validate=True)
        except (TypeError, ValueError) as exc:
            raise RecruitmentCliError(f"pinned admin {index} public key must be canonical base64") from exc
        if len(public_key) != 32 or base64.b64encode(public_key).decode("ascii") != encoded_key:
            raise RecruitmentCliError(f"pinned admin {index} public key must encode exactly 32 bytes")
        _public_key_from_bytes(public_key, label=f"pinned admin {index} public key")
        receipt = record["external_identity_receipt_sha256"]
        _sha256_argument(receipt, label=f"pinned admin {index} identity receipt")
        key_id = _derived_key_id(public_key)
        if key_id in result or entity_id in entities or public_key in public_keys:
            raise RecruitmentCliError("pinned registry administrators must be distinct")
        result[key_id] = PinnedRegistryAdmin(
            entity_id=entity_id,
            public_key=public_key,
            external_identity_receipt_sha256=receipt,
        )
        entities.add(entity_id)
        public_keys.add(public_key)
    return result


def _required_path(positional: str | None, option: str | None, *, label: str) -> str:
    if positional and option:
        raise RecruitmentCliError(f"{label} was supplied more than once")
    value = positional or option
    if not value:
        raise RecruitmentCliError(f"{label} is required")
    return value


def _cmd_key_id(args: argparse.Namespace) -> dict[str, Any]:
    path = _required_path(args.path, args.public_key, label="public key path")
    return {"schema": CLI_SCHEMA, "key_id": _key_id_from_file(path)}


def _cmd_signing_message(args: argparse.Namespace) -> dict[str, Any]:
    kind = _required_path(args.artifact_kind, args.kind, label="artifact kind")
    if kind not in _ARTIFACT_DOMAINS:
        raise RecruitmentCliError(f"artifact kind is not registered: {kind}")
    path = _required_path(args.payload_path, args.payload, label="payload path")
    payload, raw = _read_canonical_json(path, label="signing payload")
    message = signing_message(_ARTIFACT_DOMAINS[kind], payload)
    return {
        "schema": CLI_SCHEMA,
        "artifact_kind": kind,
        "payload_sha256": hashlib.sha256(raw).hexdigest(),
        "signing_message_base64": base64.b64encode(message).decode("ascii"),
    }


def _cmd_assess(args: argparse.Namespace) -> dict[str, Any]:
    bundle_path = _required_path(args.trust_bundle_path, args.trust_bundle, label="trust bundle path")
    admins_path = _required_path(args.pinned_admins_path, args.pinned_admins, label="pinned-admin config path")
    admins = _pinned_admins(admins_path, args.pinned_admins_sha256)
    verdict = assess_population_trust_file(
        bundle_path,
        pinned_registry_admins=admins,
        external_verifier=None,
    )
    if verdict.get("state") == "STRUCTURAL_TRUST_BUNDLE_VALID_REQUIRES_EXTERNAL_VERIFIER":
        for field, expected in {
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "unit_upload_permits": [],
            "sealed_holdout_accessed": False,
        }.items():
            if verdict.get(field) != expected:
                raise RecruitmentCliError(f"assessment returned unexpected authority field: {field}")
        return verdict
    # A malformed or semantically invalid bundle is still reported as the
    # attestation module's fail-closed verdict, but the CLI marks the input
    # invalid via its nonzero exit status in main().
    return verdict


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=_ArgumentParser
    )

    key_id = commands.add_parser("key-id", help="derive an Ed25519 public-key id")
    key_id.add_argument("path", nargs="?")
    key_id.add_argument("--public-key")

    message = commands.add_parser("signing-message", help="derive a registered signing preimage")
    message.add_argument("artifact_kind", nargs="?")
    message.add_argument("payload_path", nargs="?")
    message.add_argument("--kind")
    message.add_argument("--payload")

    assess = commands.add_parser("assess", help="assess one trust bundle without authority")
    assess.add_argument("trust_bundle_path", nargs="?")
    assess.add_argument("pinned_admins_path", nargs="?")
    assess.add_argument("--trust-bundle")
    assess.add_argument("--pinned-admins")
    assess.add_argument("--pinned-admins-sha256", required=True)
    return parser


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.write(canonical_json_bytes(dict(value)).decode("utf-8") + "\n")


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "key-id":
            report = _cmd_key_id(args)
            exit_code = 0
        elif args.command == "signing-message":
            report = _cmd_signing_message(args)
            exit_code = 0
        elif args.command == "assess":
            report = _cmd_assess(args)
            exit_code = 0 if report.get("state") == "STRUCTURAL_TRUST_BUNDLE_VALID_REQUIRES_EXTERNAL_VERIFIER" else 2
        else:
            raise RecruitmentCliError("unknown command")
    except (RecruitmentCliError, OSError, TypeError, ValueError) as exc:
        _emit({"schema": CLI_SCHEMA, "error": str(exc)})
        return 2
    _emit(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CLI_SCHEMA", "PINNED_ADMINS_SCHEMA", "RecruitmentCliError", "main"]
