#!/usr/bin/env python3
"""Read-only v6.2.4 release-root and population trust assessment.

This CLI cannot modify the code allowlist, issue permits, publish a campaign
root, access the sealed holdout, or upload an archive.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path
import sys
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation_v6_2.attestation_v623 import read_canonical_trust_bundle
from evaluation_v6_2.integration_v622 import canonical_json_bytes
from evaluation_v6_2.release_v624 import (
    RECRUITMENT_RELEASE_ROOT_ALLOWLIST,
    ReleaseV624Error,
    assess_population_release_files,
    validate_release_root,
)


CLI_SCHEMA = "eval.v6.2.4.release-cli-result"


class ReleaseCliError(ValueError):
    """A release CLI argument or input is unsafe or invalid."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ReleaseCliError(message)


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.write(canonical_json_bytes(dict(value)).decode("utf-8") + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    inspect = commands.add_parser(
        "inspect-root", help="validate root structure without granting authority"
    )
    inspect.add_argument("release_root")
    assess = commands.add_parser(
        "assess", help="run the allowlisted exact-file population trust gate"
    )
    assess.add_argument("release_root")
    assess.add_argument("campaign_bundle")
    assess.add_argument("release_packet")
    assess.add_argument("--expected-challenge-nonce", required=True)
    return parser


def _inspect_root(path: str) -> dict[str, Any]:
    raw = read_canonical_trust_bundle(path)
    parsed = validate_release_root(raw, require_allowlisted=False)
    allowlisted = parsed["sha256"] in RECRUITMENT_RELEASE_ROOT_ALLOWLIST
    return {
        "schema": CLI_SCHEMA,
        "state": (
            "RELEASE_ROOT_STRUCTURALLY_VALID_ALLOWLISTED"
            if allowlisted
            else "RELEASE_ROOT_STRUCTURALLY_VALID_NOT_ALLOWLISTED"
        ),
        "release_root_sha256": parsed["sha256"],
        "code_allowlisted": allowlisted,
        "recruitment_intake_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "unit_upload_permits": [],
        "sealed_holdout_accessed": False,
    }


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "inspect-root":
            report = _inspect_root(args.release_root)
            exit_code = 0
        elif args.command == "assess":
            report = assess_population_release_files(
                release_root_path=args.release_root,
                campaign_bundle_path=args.campaign_bundle,
                release_packet_path=args.release_packet,
                expected_verification_challenge_nonce=args.expected_challenge_nonce,
            )
            exit_code = (
                0
                if report.get("state")
                == "POPULATION_TRUST_GATE_PASSED_LOCAL_EVIDENCE_PENDING"
                else 2
            )
        else:
            raise ReleaseCliError("unknown command")
    except (OSError, TypeError, ValueError, ReleaseV624Error) as exc:
        report = {
            "schema": CLI_SCHEMA,
            "state": "POPULATION_INFEASIBLE",
            "failure": str(exc),
            "recruitment_intake_authorized": False,
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "unit_upload_permits": [],
            "sealed_holdout_accessed": False,
        }
        exit_code = 2
    _emit(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CLI_SCHEMA", "ReleaseCliError", "main"]
