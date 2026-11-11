#!/usr/bin/env python3
"""Read-only v6.2.5 release-root and population trust assessment.

This CLI cannot modify bootstrap trust, issue permits, publish a campaign root,
access the sealed holdout, or upload an archive. A successful assessment only
opens the later local-evidence stage and atomically consumes its challenge.
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
from evaluation_v6_2 import release_v625


CLI_SCHEMA = "eval.v6.2.5.release-cli-result"


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
        "assess", help="run the bootstrap-authorized exact-file population trust gate"
    )
    assess.add_argument("release_root")
    assess.add_argument("release_root_authorization")
    assess.add_argument("campaign_bundle")
    assess.add_argument("release_packet")
    assess.add_argument("--challenge-replay-db", required=True)
    assess.add_argument("--expected-challenge-nonce", required=True)
    return parser


def _inspect_root(path: str) -> dict[str, Any]:
    raw = read_canonical_trust_bundle(path)
    parsed = release_v625.validate_release_root(raw)
    return {
        "schema": CLI_SCHEMA,
        "state": "RELEASE_ROOT_STRUCTURALLY_VALID_AUTHORITY_PENDING",
        "release_root_sha256": parsed["sha256"],
        "bootstrap_trust_configured": release_v625.BOOTSTRAP_TRUST_CONFIG is not None,
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
            report = release_v625.assess_population_release_files(
                release_root_path=args.release_root,
                release_root_authorization_path=args.release_root_authorization,
                campaign_bundle_path=args.campaign_bundle,
                release_packet_path=args.release_packet,
                challenge_replay_db_path=args.challenge_replay_db,
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
    except (OSError, TypeError, ValueError, release_v625.ReleaseV625Error) as exc:
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
