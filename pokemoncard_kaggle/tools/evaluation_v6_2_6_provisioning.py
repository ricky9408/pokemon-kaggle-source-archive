#!/usr/bin/env python3
"""Read-only v6.2.6 external provisioning readiness assessment.

This command can only report candidate evidence completeness. It cannot pin a
trust policy, issue permits, authorize uploads, or access the sealed holdout.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation_v6_2.integration_v622 import canonical_json_bytes, canonical_json_loads
from evaluation_v6_2 import provisioning_v626


CLI_SCHEMA = "eval.v6.2.6.provisioning-cli-result"
INVOCATION_SCHEMA = "eval.v6.2.6.provisioning-assessment-invocation"
_MAX_FILE_BYTES = 512 * 1024 * 1024
_INVOCATION_FIELDS = frozenset(
    {
        "schema",
        "candidate_trust_policy_path",
        "candidate_trust_policy_sha256",
        "provisioning_packet_path",
        "evidence_nodes_jsonl_path",
        "evidence_edges_jsonl_path",
        "evidence_payload_manifest_jsonl_path",
        "evidence_payload_directory",
    }
)
_FORBIDDEN_TOKENS = ("sealed", "holdout")


class ProvisioningCliError(ValueError):
    """A v6.2.6 provisioning CLI input is unsafe or malformed."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ProvisioningCliError(message)


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.write(canonical_json_bytes(dict(value)).decode("utf-8") + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    commands.add_parser("status", help="report evidence-absent provisioning status")
    assess = commands.add_parser("assess", help="assess one canonical provisioning invocation")
    assess.add_argument("invocation")
    return parser


def _relative(value: Any, label: str) -> PurePosixPath:
    if type(value) is not str or not value or "\\" in value or "\0" in value:
        raise ProvisioningCliError(f"{label} must be a safe POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ProvisioningCliError(f"{label} must be a normalized relative path")
    if any(token in part.casefold() for part in path.parts for token in _FORBIDDEN_TOKENS):
        raise ProvisioningCliError(f"{label} may not address sealed or holdout material")
    return path


def _read_secure(path: Path, *, base: Path, label: str) -> bytes:
    resolved_base = base.resolve(strict=True)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_base)
    except (OSError, ValueError) as exc:
        raise ProvisioningCliError(f"{label} escapes or is absent from the invocation directory") from exc
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProvisioningCliError(f"{label} must be a regular non-symlink file")
    if before.st_uid != os.getuid() or before.st_mode & 0o022:
        raise ProvisioningCliError(f"{label} must be owner-controlled and not group/world writable")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise ProvisioningCliError(f"{label} changed while being opened")
        if after.st_size > _MAX_FILE_BYTES:
            raise ProvisioningCliError(f"{label} exceeds the file-size ceiling")
        data = bytearray()
        while len(data) < after.st_size:
            chunk = os.read(fd, min(1024 * 1024, after.st_size - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != after.st_size:
            raise ProvisioningCliError(f"{label} was truncated while reading")
        return bytes(data)
    finally:
        os.close(fd)


def _read_json(path: Path, *, base: Path, label: str) -> Any:
    raw = _read_secure(path, base=base, label=label)
    try:
        value = canonical_json_loads(raw)
    except Exception as exc:
        raise ProvisioningCliError(f"{label} is not canonical JSON") from exc
    if canonical_json_bytes(value) != raw:
        raise ProvisioningCliError(f"{label} is not exact canonical JSON")
    return value


def _read_jsonl(path: Path, *, base: Path, label: str) -> bytes:
    raw = _read_secure(path, base=base, label=label)
    if not raw.endswith(b"\n"):
        raise ProvisioningCliError(f"{label} must be LF-terminated canonical JSONL")
    for index, line in enumerate(raw[:-1].split(b"\n")):
        if not line:
            raise ProvisioningCliError(f"{label} line {index} is empty")
        try:
            value = canonical_json_loads(line)
        except Exception as exc:
            raise ProvisioningCliError(f"{label} line {index} is not canonical JSON") from exc
        if canonical_json_bytes(value) != line:
            raise ProvisioningCliError(f"{label} line {index} is not exact canonical JSON")
    return raw


def _load_payloads(manifest: bytes, *, directory: Path, base: Path) -> dict[str, bytes]:
    digests: list[str] = []
    for index, line in enumerate(manifest[:-1].split(b"\n")):
        try:
            item = canonical_json_loads(line)
        except Exception as exc:
            raise ProvisioningCliError(f"payload manifest line {index} is not canonical JSON") from exc
        if type(item) is not dict or canonical_json_bytes(item) != line:
            raise ProvisioningCliError(f"payload manifest line {index} is not a canonical object")
        digest = item.get("payload_sha256")
        if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ProvisioningCliError(f"payload manifest line {index} has an invalid digest")
        if digest in digests:
            raise ProvisioningCliError("payload manifest contains a duplicate digest")
        digests.append(digest)
    if not directory.is_dir() or directory.is_symlink():
        raise ProvisioningCliError("evidence payload directory must be a real directory")
    payloads = {
        digest: _read_secure(directory / f"{digest}.payload", base=base, label=f"payload {digest}")
        for digest in digests
    }
    actual = {item.name for item in directory.iterdir()}
    expected = {f"{digest}.payload" for digest in digests}
    if actual != expected:
        raise ProvisioningCliError("payload directory does not exactly match the closed manifest")
    return payloads


def load_invocation(path: str | Path) -> dict[str, Any]:
    invocation_path = Path(path)
    base = invocation_path.parent.resolve(strict=True)
    value = _read_json(invocation_path, base=base, label="provisioning assessment invocation")
    if type(value) is not dict or set(value) != _INVOCATION_FIELDS or value["schema"] != INVOCATION_SCHEMA:
        raise ProvisioningCliError("provisioning invocation schema or fields are invalid")

    def artifact(field: str, label: str) -> Path:
        return base / Path(_relative(value[field], field))

    manifest_path = artifact("evidence_payload_manifest_jsonl_path", "payload manifest")
    manifest = _read_jsonl(manifest_path, base=base, label="payload manifest")
    payload_directory = base / Path(_relative(value["evidence_payload_directory"], "evidence_payload_directory"))
    return {
        "candidate_trust_policy": _read_json(artifact("candidate_trust_policy_path", "candidate trust policy"), base=base, label="candidate trust policy"),
        "candidate_trust_policy_sha256": value["candidate_trust_policy_sha256"],
        "provisioning_packet": _read_json(artifact("provisioning_packet_path", "provisioning packet"), base=base, label="provisioning packet"),
        "nodes_jsonl": _read_jsonl(artifact("evidence_nodes_jsonl_path", "evidence nodes"), base=base, label="evidence nodes"),
        "edges_jsonl": _read_jsonl(artifact("evidence_edges_jsonl_path", "evidence edges"), base=base, label="evidence edges"),
        "payload_manifest_jsonl": manifest,
        "payloads": _load_payloads(manifest, directory=payload_directory, base=base),
    }


def _status() -> dict[str, Any]:
    report = provisioning_v626.current_external_provisioning_status()
    report = dict(report)
    report["schema"] = CLI_SCHEMA
    return report


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "status":
            report = _status()
            exit_code = 2
        elif args.command == "assess":
            report = provisioning_v626.assess_external_provisioning_readiness(**load_invocation(args.invocation))
            exit_code = (
                0
                if report.get("state")
                == "CANDIDATE_EXTERNAL_SERVICES_PACKET_STRUCTURALLY_COMPLETE_REQUIRES_LIVE_CHALLENGE_AND_POLICY_PIN_REVIEW"
                else 2
            )
        else:
            raise ProvisioningCliError("unknown command")
    except (OSError, TypeError, ValueError) as exc:
        report = provisioning_v626.fail_closed_provisioning_verdict(
            "PROVISIONING_PACKET_INVALID", str(exc)
        )
        report["schema"] = CLI_SCHEMA
        exit_code = 2
    _emit(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CLI_SCHEMA", "INVOCATION_SCHEMA", "ProvisioningCliError", "load_invocation", "main"]
