#!/usr/bin/env python3
"""Read-only, fail-closed population readiness audit for evaluator v5.1.

Scout data is useful for a shadow population census only.  It cannot establish
ancestry independence: this module deliberately has no ancestry inference and
always reports zero production-verified families because authenticated
ancestry-component attestations are an external authority.
"""

from __future__ import annotations

import argparse
import csv
from collections.abc import Iterable, Mapping
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


SCHEMA = "evaluation_v5_1_population_readiness_audit_v1"
PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
REQUIRED_FAMILIES = 20
REQUIRED_GAMES_PER_FAMILY = 200

# Familiar aliases make the frozen protocol values easy to consume without
# allowing callers to supply replacement thresholds.
FAMILY_COUNT = REQUIRED_FAMILIES
GAMES_PER_FAMILY = REQUIRED_GAMES_PER_FAMILY

_CSV_NAME = "team_submissions.csv"
_FORBIDDEN_COMPONENT = re.compile(r"(?:holdout|sealed)", re.IGNORECASE)
_TEAM_ACCOUNT_KEYS = frozenset(
    {
        "accountid",
        "teamid",
    }
)
_SUBMISSION_KEYS = frozenset(
    {
        "id",
        "submissionid",
        "submission",
    }
)
_ACTIVE_KEYS = frozenset(
    {
        "active",
        "isactive",
        "current",
        "iscurrent",
    }
)


class PopulationReadinessError(ValueError):
    """An explicit scout input is unsafe or malformed."""


def canonical_json_bytes(value: object) -> bytes:
    """Serialize JSON deterministically using the repository's ASCII style."""

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def render_json(report: Mapping[str, Any]) -> str:
    """Return the deterministic wire representation used by the CLI."""

    return canonical_json_bytes(dict(report)).decode("ascii")


def _normal_key(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def _forbidden_component(component: str) -> bool:
    return bool(_FORBIDDEN_COMPONENT.search(component))


def _validate_path_components(path: Path, *, label: str) -> None:
    """Reject lexical traversal, forbidden names, and symlink components."""

    if any(part == ".." for part in path.parts):
        raise PopulationReadinessError(f"{label} contains a path escape: {path}")
    if any(_forbidden_component(part) for part in path.parts if part not in {os.sep, ""}):
        raise PopulationReadinessError(f"{label} contains a holdout/sealed path component: {path}")

    current = Path(path.anchor) if path.anchor else Path()
    for part in path.parts:
        if part in {path.anchor, ""}:
            continue
        current = current / part
        try:
            mode = current.lstat()
        except FileNotFoundError:
            # The caller reports missing final paths separately.  A missing
            # component cannot be a symlink and is not safe to audit anyway.
            continue
        if current.is_symlink():
            raise PopulationReadinessError(f"{label} contains a symlink: {current}")


def _explicit_root(value: str | os.PathLike[str], *, index: int) -> Path:
    raw = Path(value)
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    _validate_path_components(raw, label=f"scout directory {index}")
    try:
        root = raw.resolve(strict=True)
    except OSError as exc:
        raise PopulationReadinessError(f"scout directory {index} cannot be resolved: {raw}") from exc
    if root.is_symlink() or not root.is_dir():
        raise PopulationReadinessError(f"scout directory {index} must be a real directory: {raw}")
    _validate_path_components(root, label=f"scout directory {index}")
    return root


def _validate_entry(root: Path, entry: Path) -> None:
    _validate_path_components(entry, label="scout entry")
    try:
        entry.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise PopulationReadinessError(f"scout entry escapes its explicit directory: {entry}") from exc
    if entry.is_symlink():
        raise PopulationReadinessError(f"scout entry is a symlink: {entry}")


def _scan_csv_paths(root: Path) -> list[Path]:
    """Find only team_submissions.csv below one explicit, trusted root."""

    found: list[Path] = []
    for current_string, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_string)
        _validate_entry(root, current)
        directory_names.sort()
        file_names.sort()
        for name in directory_names + file_names:
            _validate_entry(root, current / name)
        for name in file_names:
            if name == _CSV_NAME:
                candidate = current / name
                if not candidate.is_file():
                    raise PopulationReadinessError(f"{candidate} is not a regular file")
                found.append(candidate)
    return found


def _cell(
    row: Mapping[str | None, str | None],
    normalized: Mapping[str, str],
    keys: frozenset[str],
    *,
    priority: tuple[str, ...] | None = None,
) -> str:
    ordered_keys = priority or tuple(sorted(keys))
    for key in ordered_keys:
        column = normalized.get(key)
        if column is not None:
            value = row.get(column)
            if value is not None and value.strip():
                return value.strip()
    return ""


def _row_is_active(row: Mapping[str | None, str | None], normalized: Mapping[str, str]) -> bool:
    for key in ("active", "isactive", "current", "iscurrent"):
        column = normalized.get(key)
        if column is None:
            continue
        value = (row.get(column) or "").strip().lower()
        if value in {"0", "false", "no", "inactive", "retired", "superseded"}:
            return False
        if value in {"1", "true", "yes", "active", "current"} or not value:
            return True
    return True


def _shadow_id_from_parent(csv_path: Path, root: Path) -> str:
    """Use the scout's team directory as an observational shadow identity."""

    parent = csv_path.parent
    if parent == root:
        return ""
    # Existing scouts use ``<rank>_<team name>_<numeric team id>``.  The
    # suffix is only a census key; it is never treated as an ancestry key.
    match = re.search(r"(?:^|[_-])(\d+)$", parent.name)
    return match.group(1) if match else parent.name


def _read_team_submissions(
    csv_path: Path,
    root: Path,
) -> tuple[set[str], set[str], int, str]:
    account_ids: set[str] = set()
    active_submission_ids: set[str] = set()
    active_submission_rows = 0
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = reader.fieldnames
            if not fieldnames:
                raise PopulationReadinessError(f"{csv_path} has no CSV header")
            normalized: dict[str, str] = {}
            for field in fieldnames:
                if field is None:
                    raise PopulationReadinessError(f"{csv_path} has an unnamed CSV column")
                key = _normal_key(field)
                if not key or key in normalized:
                    raise PopulationReadinessError(f"{csv_path} has duplicate/invalid CSV columns")
                normalized[key] = field
            if not _SUBMISSION_KEYS.intersection(normalized):
                raise PopulationReadinessError(f"{csv_path} has no submission ID column")

            explicit_account_seen = False
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    raise PopulationReadinessError(f"{csv_path} row {row_number} has too many columns")
                account_values = [
                    (row.get(column) or "").strip()
                    for key, column in normalized.items()
                    if key in _TEAM_ACCOUNT_KEYS
                ]
                for account_id in account_values:
                    if account_id:
                        explicit_account_seen = True
                        account_ids.add(account_id)
                if _row_is_active(row, normalized):
                    submission_id = _cell(
                        row,
                        normalized,
                        _SUBMISSION_KEYS,
                        priority=("id", "submissionid", "submission"),
                    )
                    if submission_id:
                        active_submission_ids.add(submission_id)
                        active_submission_rows += 1
            if not explicit_account_seen:
                fallback = _shadow_id_from_parent(csv_path, root)
                if fallback:
                    account_ids.add(fallback)
    except UnicodeDecodeError as exc:
        raise PopulationReadinessError(f"{csv_path} is not UTF-8 CSV") from exc
    except OSError as exc:
        raise PopulationReadinessError(f"cannot read {csv_path}") from exc
    return account_ids, active_submission_ids, active_submission_rows, str(csv_path)


def audit_population_readiness(
    scout_directories: Iterable[str | os.PathLike[str]],
) -> dict[str, Any]:
    """Audit explicit scout directories without granting production authority."""

    values = list(scout_directories)
    if not values:
        raise PopulationReadinessError("at least one explicit scout directory is required")
    roots = sorted({_explicit_root(value, index=index) for index, value in enumerate(values)}, key=str)

    account_ids: set[str] = set()
    active_submission_ids: set[str] = set()
    active_submission_row_count = 0
    csv_paths: set[str] = set()
    for root in roots:
        for csv_path in _scan_csv_paths(root):
            local_accounts, local_submissions, local_active_rows, path_text = (
                _read_team_submissions(csv_path, root)
            )
            account_ids.update(local_accounts)
            active_submission_ids.update(local_submissions)
            active_submission_row_count += local_active_rows
            csv_paths.add(path_text)

    # This is intentionally independent of all scout counts.  A local process
    # cannot authenticate ancestry components, and similarity is not evidence.
    production_verified_family_count = 0
    production_population_feasible = False
    content: dict[str, Any] = {
        "schema": SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "scout_directories": [str(root) for root in roots],
        "scout_directory_count": len(roots),
        "team_submissions_file_count": len(csv_paths),
        "team_directory_count": len({str(Path(path).parent) for path in csv_paths}),
        "distinct_team_account_id_count": len(account_ids),
        "distinct_team_account_ids": sorted(account_ids),
        "active_submission_id_count": len(active_submission_ids),
        "active_submission_row_count": active_submission_row_count,
        "active_submission_ids": sorted(active_submission_ids),
        "shadow_account_cluster_count": len(account_ids),
        "shadow_evidence_use": "VETO_ONLY_NON_AUTHORITATIVE",
        "shadow_population_feasible": len(account_ids) >= REQUIRED_FAMILIES,
        "externally_authenticated_ancestry_attestations": False,
        "production_verified_family_count": production_verified_family_count,
        "production_population_feasible": production_population_feasible,
        "required_family_count": REQUIRED_FAMILIES,
        "required_families": REQUIRED_FAMILIES,
        "required_games_per_family": REQUIRED_GAMES_PER_FAMILY,
        "games_per_family": REQUIRED_GAMES_PER_FAMILY,
        "authority": False,
        "candidate_development_authorized": False,
        "holdout": False,
        "holdout_access_authorized": False,
        "sealed_holdout_access_authorized": False,
        "submission": False,
        "submission_authorized": False,
        "production_submission_authorized": False,
        "decision": "NO_SUBMIT_IDENTIFIABILITY",
        "notes": [
            "shadow account clusters are descriptive and veto-only",
            "account, team, deck, policy, archive, and semantic similarity are not ancestry attestations",
            "this audit cannot authenticate ancestry independence",
        ],
    }
    return content


# Compatibility aliases for callers that name the operation after the input.
audit_scout_population = audit_population_readiness
build_population_readiness = audit_population_readiness


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "scout_directories",
        nargs="*",
        type=Path,
        help="one or more explicit scout directories",
    )
    parser.add_argument(
        "--scout-dir",
        dest="scout_directory_options",
        action="append",
        type=Path,
        default=[],
        help="additional explicit scout directory; may be repeated",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    directories = [*args.scout_directories, *args.scout_directory_options]
    try:
        report = audit_population_readiness(directories)
    except PopulationReadinessError as exc:
        print(f"population-readiness-error: {exc}", file=sys.stderr)
        return 2
    print(render_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "FAMILY_COUNT",
    "GAMES_PER_FAMILY",
    "PopulationReadinessError",
    "PROTOCOL_ID",
    "REQUIRED_FAMILIES",
    "REQUIRED_GAMES_PER_FAMILY",
    "SCHEMA",
    "audit_population_readiness",
    "audit_scout_population",
    "build_population_readiness",
    "canonical_json_bytes",
    "main",
    "render_json",
]
