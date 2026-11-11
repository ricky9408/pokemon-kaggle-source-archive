#!/usr/bin/env python3
"""Read-only service-bound v6.2.6 population trust assessment.

This CLI never uploads, issues a permit, publishes a preregistration root, or
opens the sealed holdout. There is deliberately no runtime trust-policy option.
Until a separately reviewed literal policy is code-pinned, every assessment
returns BOOTSTRAP_CONFIG_ABSENT before campaign artifacts are read.
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

from evaluation_v6_2.integration_v622 import (
    canonical_json_bytes,
    canonical_json_loads,
)
from evaluation_v6_2 import release_v626


CLI_SCHEMA = "eval.v6.2.6.release-cli-result"
INVOCATION_SCHEMA = "eval.v6.2.6.assessment-invocation"
_MAX_FILE_BYTES = 512 * 1024 * 1024


class ReleaseCliV626Error(ValueError):
    """A v6.2.6 CLI input is unsafe or malformed."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ReleaseCliV626Error(message)


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.write(canonical_json_bytes(dict(value)).decode("utf-8") + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    commands.add_parser("status", help="report whether an exact external policy is pinned")
    assess = commands.add_parser("assess", help="assess one canonical invocation artifact pack")
    assess.add_argument("invocation")
    return parser


def _relative(value: Any, label: str) -> PurePosixPath:
    if type(value) is not str or not value or "\\" in value or "\0" in value:
        raise ReleaseCliV626Error(f"{label} must be a safe POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseCliV626Error(f"{label} must be a normalized relative path")
    return path


def _read_secure(path: Path, *, base: Path, label: str) -> bytes:
    resolved_base = base.resolve(strict=True)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_base)
    except (OSError, ValueError) as exc:
        raise ReleaseCliV626Error(f"{label} escapes or is absent from the invocation directory") from exc
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ReleaseCliV626Error(f"{label} must be a regular non-symlink file")
    if before.st_uid != os.getuid() or before.st_mode & 0o022:
        raise ReleaseCliV626Error(f"{label} must be owner-controlled and not group/world writable")
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
            raise ReleaseCliV626Error(f"{label} changed while being opened")
        if after.st_size > _MAX_FILE_BYTES:
            raise ReleaseCliV626Error(f"{label} exceeds the file-size ceiling")
        data = b""
        while len(data) < after.st_size:
            chunk = os.read(fd, min(1024 * 1024, after.st_size - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) != after.st_size:
            raise ReleaseCliV626Error(f"{label} was truncated while reading")
        return data
    finally:
        os.close(fd)


def _read_json(path: Path, *, base: Path, label: str) -> Any:
    raw = _read_secure(path, base=base, label=label)
    try:
        value = canonical_json_loads(raw)
    except Exception as exc:
        raise ReleaseCliV626Error(f"{label} is not canonical JSON") from exc
    if canonical_json_bytes(value) != raw:
        raise ReleaseCliV626Error(f"{label} is not exact canonical JSON")
    return value


_INVOCATION_FIELDS = frozenset(
    {
        "schema",
        "witness_transition_path",
        "opening_witness_head_path",
        "closing_witness_head_path",
        "opening_time_receipts_path",
        "closing_time_receipts_path",
        "evidence_nodes_jsonl_path",
        "evidence_edges_jsonl_path",
        "evidence_payload_manifest_jsonl_path",
        "evidence_payload_directory",
        "evidence_graph_root_sha256",
        "campaign_bundle_root_sha256",
        "verification_packet_root_sha256",
        "invocation_challenge_sha256",
        "population_analysis_root_sha256",
        "evidence_input_graph_root_sha256",
        "pair_classification_graph_root_sha256",
        "component_assignment_root_sha256",
        "pair_analysis_root_sha256s",
        "principal_assignment_root_sha256s",
        "verification_receipts_path",
        "observed_witness_transitions_path",
    }
)


def _load_payloads(manifest_bytes: bytes, *, directory: Path, base: Path) -> dict[str, bytes]:
    if not manifest_bytes.endswith(b"\n"):
        raise ReleaseCliV626Error("payload manifest must be LF-terminated JSONL")
    digests: list[str] = []
    for index, line in enumerate(manifest_bytes[:-1].split(b"\n")):
        try:
            item = canonical_json_loads(line)
        except Exception as exc:
            raise ReleaseCliV626Error(f"payload manifest line {index} is not canonical JSON") from exc
        if type(item) is not dict or canonical_json_bytes(item) != line:
            raise ReleaseCliV626Error(f"payload manifest line {index} is not a canonical object")
        digest = item.get("payload_sha256")
        if type(digest) is not str or len(digest) != 64:
            raise ReleaseCliV626Error(f"payload manifest line {index} has an invalid digest")
        digests.append(digest)
    payloads = {
        digest: _read_secure(
            directory / f"{digest}.payload",
            base=base,
            label=f"payload {digest}",
        )
        for digest in digests
    }
    actual_names = {
        item.name
        for item in directory.iterdir()
        if item.is_file() or item.is_symlink()
    }
    expected_names = {f"{digest}.payload" for digest in digests}
    if actual_names != expected_names:
        raise ReleaseCliV626Error("payload directory does not exactly match the closed manifest")
    return payloads


def load_invocation(path: str | Path) -> dict[str, Any]:
    invocation_path = Path(path)
    base = invocation_path.parent.resolve(strict=True)
    value = _read_json(invocation_path, base=base, label="assessment invocation")
    if type(value) is not dict or set(value) != _INVOCATION_FIELDS or value["schema"] != INVOCATION_SCHEMA:
        raise ReleaseCliV626Error("assessment invocation schema or fields are invalid")

    def artifact(field: str, label: str) -> Path:
        return base / Path(_relative(value[field], field))

    manifest_bytes = _read_secure(
        artifact("evidence_payload_manifest_jsonl_path", "payload manifest"),
        base=base,
        label="payload manifest",
    )
    payload_directory = base / Path(_relative(value["evidence_payload_directory"], "evidence_payload_directory"))
    if not payload_directory.is_dir() or payload_directory.is_symlink():
        raise ReleaseCliV626Error("evidence payload directory must be a real directory")
    payloads = _load_payloads(manifest_bytes, directory=payload_directory, base=base)
    return {
        "witness_transition": _read_json(artifact("witness_transition_path", "witness transition"), base=base, label="witness transition"),
        "opening_witness_head": _read_json(artifact("opening_witness_head_path", "opening witness head"), base=base, label="opening witness head"),
        "closing_witness_head": _read_json(artifact("closing_witness_head_path", "closing witness head"), base=base, label="closing witness head"),
        "opening_time_receipts": _read_json(artifact("opening_time_receipts_path", "opening time receipts"), base=base, label="opening time receipts"),
        "closing_time_receipts": _read_json(artifact("closing_time_receipts_path", "closing time receipts"), base=base, label="closing time receipts"),
        "nodes_jsonl": _read_secure(artifact("evidence_nodes_jsonl_path", "evidence nodes"), base=base, label="evidence nodes"),
        "edges_jsonl": _read_secure(artifact("evidence_edges_jsonl_path", "evidence edges"), base=base, label="evidence edges"),
        "payload_manifest_jsonl": manifest_bytes,
        "payloads": payloads,
        "evidence_graph_root_sha256": value["evidence_graph_root_sha256"],
        "campaign_bundle_root_sha256": value["campaign_bundle_root_sha256"],
        "verification_packet_root_sha256": value["verification_packet_root_sha256"],
        "invocation_challenge_sha256": value["invocation_challenge_sha256"],
        "population_analysis_root_sha256": value["population_analysis_root_sha256"],
        "evidence_input_graph_root_sha256": value["evidence_input_graph_root_sha256"],
        "pair_classification_graph_root_sha256": value["pair_classification_graph_root_sha256"],
        "component_assignment_root_sha256": value["component_assignment_root_sha256"],
        "pair_analysis_root_sha256s": value["pair_analysis_root_sha256s"],
        "principal_assignment_root_sha256s": value["principal_assignment_root_sha256s"],
        "verification_receipts": _read_json(artifact("verification_receipts_path", "verification receipts"), base=base, label="verification receipts"),
        "observed_witness_transitions": _read_json(artifact("observed_witness_transitions_path", "observed witness transitions"), base=base, label="observed witness transitions"),
    }


def _status() -> dict[str, Any]:
    configured = (
        release_v626.PINNED_EXTERNAL_TRUST_POLICY is not None
        and release_v626.PINNED_EXTERNAL_TRUST_POLICY_SHA256 is not None
    )
    return {
        "schema": CLI_SCHEMA,
        "state": "EXTERNAL_TRUST_POLICY_PINNED" if configured else "BOOTSTRAP_CONFIG_ABSENT",
        "external_trust_policy_configured": configured,
        "recruitment_intake_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "permits": [],
        "sealed_holdout_accessed": False,
    }


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "status":
            report = _status()
            exit_code = 0 if report["external_trust_policy_configured"] else 2
        elif args.command == "assess":
            if (
                release_v626.PINNED_EXTERNAL_TRUST_POLICY is None
                or release_v626.PINNED_EXTERNAL_TRUST_POLICY_SHA256 is None
            ):
                report = release_v626.assess_production_population_trust()
            else:
                report = release_v626.assess_production_population_trust(**load_invocation(args.invocation))
            exit_code = 0 if report.get("state") == "POPULATION_TRUST_GATE_PASSED_LOCAL_EVIDENCE_PENDING" else 2
        else:
            raise ReleaseCliV626Error("unknown command")
    except (OSError, TypeError, ValueError) as exc:
        report = {
            "schema": CLI_SCHEMA,
            "state": "POPULATION_INFEASIBLE",
            "reason": str(exc),
            "external_authentication_verified": False,
            "population_feasible": False,
            "recruitment_intake_authorized": False,
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "permits": [],
            "sealed_holdout_accessed": False,
        }
        exit_code = 2
    _emit(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CLI_SCHEMA", "INVOCATION_SCHEMA", "ReleaseCliV626Error", "load_invocation", "main"]
