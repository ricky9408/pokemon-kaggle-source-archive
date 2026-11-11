#!/usr/bin/env python3
"""Read-only v6.3 profile status and offline conformance CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v6_2.integration_v622 import canonical_json_bytes, canonical_json_loads
from evaluation_v6_3.hybrid_trust import assess_hybrid_trust_profile, current_hybrid_status


CLI_SCHEMA = "eval.v6.3.status-cli"
_FORBIDDEN_RE = re.compile(r"(?:^|[-_. /])(sealed|holdout)(?:$|[-_. /])", re.IGNORECASE)


class StatusCliError(ValueError):
    pass


def _load_canonical_object(path: Path) -> dict[str, Any]:
    if _FORBIDDEN_RE.search(path.as_posix()):
        raise StatusCliError("v6.3 status CLI must not access sealed or holdout paths")
    try:
        info = path.lstat()
    except OSError as exc:
        raise StatusCliError("unable to stat profile input") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise StatusCliError("profile input must be a regular non-symlink file")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise StatusCliError("profile input must not be group- or world-writable")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StatusCliError("unable to read profile input") from exc
    if raw.startswith(b"\xef\xbb\xbf") or raw.endswith(b"\n") or b"\r" in raw:
        raise StatusCliError("profile must be canonical UTF-8 JSON without framing whitespace")
    try:
        value = canonical_json_loads(raw)
    except Exception as exc:
        raise StatusCliError("profile is not valid canonical JSON") from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise StatusCliError("profile is not a canonical JSON object")
    return value


def _report(value: dict[str, Any]) -> dict[str, Any]:
    return {"schema": CLI_SCHEMA, **value}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="report current zero-authority state")
    assess = subparsers.add_parser("assess-profile", help="assess one candidate profile offline")
    assess.add_argument("profile", type=Path)
    assess.add_argument("--expected-sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "status":
            report = current_hybrid_status()
        else:
            profile_path = args.profile if args.profile.is_absolute() else Path.cwd() / args.profile
            report = assess_hybrid_trust_profile(
                _load_canonical_object(profile_path),
                expected_sha256=args.expected_sha256,
            )
        print(json.dumps(_report(report), sort_keys=True, separators=(",", ":")))
        return 0 if report.get("hybrid_profile_structurally_valid") else 2
    except (StatusCliError, OSError, ValueError) as exc:
        report = current_hybrid_status()
        report["state"] = "V6_3_STATUS_INPUT_INVALID"
        report["detail"] = str(exc)
        print(json.dumps(_report(report), sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
