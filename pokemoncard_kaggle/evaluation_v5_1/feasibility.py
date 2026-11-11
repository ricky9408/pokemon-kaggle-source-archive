"""Negative-authority feasibility arithmetic for the v5.1 exact-pair evaluator.

This module accepts only two small, explicit JSON snapshots.  It performs no
discovery, network access, evidence authentication, or authority transition.
The result is therefore a planning diagnostic only: every authority bit is
forced to ``False`` even when the supplied counts are mathematically enough.
"""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Mapping


SCHEMA = "evaluation_v5_1_exact_pair_feasibility_v1"
CONSTRAINTS_SCHEMA = "evaluation_v5_1_exact_pair_feasibility_constraints_v1"
STATUS_SCHEMA = "evaluation_v5_1_status_v1"
DECISION_INFEASIBLE = "INFEASIBLE_WITH_CURRENT_EVIDENCE_AND_AUTHORIZED_SUBMISSION_BUDGET"
DECISION_COUNTS_SATISFIED = "FEASIBILITY_COUNTS_SATISFIED_REQUIRES_SEPARATE_PRODUCTION_VERIFICATION"

REQUIRED_INDEPENDENT_FAMILIES = 20
MAXIMUM_FINAL_SUBMISSIONS = 1
RESERVED_FINAL_SUBMISSIONS = 1
AUTHORIZED_NONFINAL_RESEARCH_SUBMISSIONS = 0
CURRENTLY_ACTIVE_OWNED_EXACT_ARCHIVES = 2
CURRENTLY_ACTIVE_OWNED_INDEPENDENT_COMPONENTS = 1
ONE_NEW_INDEPENDENT_FAMILY_PER_SUBMISSION_UPPER_BOUND = 1
EXTERNAL_EXACT_PAIR_INTAKE_AVAILABLE = False

CONSTRAINT_KEYS = frozenset(
    {
        "required_independent_families",
        "schema",
        "maximum_final_submissions",
        "reserved_final_submissions",
        "authorized_nonfinal_research_submissions",
        "currently_active_owned_exact_archives",
        "currently_active_owned_independent_components",
        "one_new_independent_family_per_submission_upper_bound",
        "external_exact_pair_intake_available",
    }
)
STATUS_REQUIRED_KEYS = frozenset(
    {
        "schema",
        "prospective_required_family_count",
        "prospective_authenticated_independent_family_count",
        "paired_evidence_authenticated_unit_count",
        "prospective_production_verifier_available",
        "submission_authorized",
    }
)

_FORBIDDEN_COMPONENTS = ("sealed", "holdout")


class FeasibilityError(ValueError):
    """An explicit feasibility input or output path is unsafe or malformed."""


def canonical_json_bytes(value: object) -> bytes:
    """Return deterministic ASCII JSON for the report wire format."""

    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise FeasibilityError(f"value is not deterministic JSON: {exc}") from exc


def render_json(report: Mapping[str, Any]) -> str:
    """Render a report deterministically for stdout and tests."""

    return canonical_json_bytes(dict(report)).decode("ascii")


def _reject_json_constant(value: str) -> None:
    raise FeasibilityError(f"JSON constant {value!r} is forbidden")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FeasibilityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _forbidden_component(component: str) -> bool:
    lowered = component.casefold()
    return any(token in lowered for token in _FORBIDDEN_COMPONENTS)


def _absolute_path(value: str | os.PathLike[str], *, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    if any(part == ".." for part in path.parts):
        raise FeasibilityError(f"{label} contains path traversal: {path}")
    if any(_forbidden_component(part) for part in path.parts if part not in {path.anchor, ""}):
        raise FeasibilityError(f"{label} contains a forbidden sealed/holdout path component: {path}")
    return path


def _validate_existing_file(value: str | os.PathLike[str], *, label: str) -> Path:
    path = _absolute_path(value, label=label)
    current = Path(path.anchor) if path.anchor else Path()
    for part in path.parts:
        if part in {path.anchor, ""}:
            continue
        current = current / part
        try:
            if current.is_symlink():
                raise FeasibilityError(f"{label} contains a symlink: {current}")
        except OSError as exc:
            raise FeasibilityError(f"cannot inspect {label}: {current}") from exc
    try:
        info = path.lstat()
    except OSError as exc:
        raise FeasibilityError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise FeasibilityError(f"{label} is a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise FeasibilityError(f"{label} must be a regular file: {path}")
    return path


def _validate_existing_directory(value: str | os.PathLike[str], *, label: str) -> Path:
    path = _absolute_path(value, label=label)
    current = Path(path.anchor) if path.anchor else Path()
    for part in path.parts:
        if part in {path.anchor, ""}:
            continue
        current = current / part
        try:
            if current.is_symlink():
                raise FeasibilityError(f"{label} contains a symlink: {current}")
        except OSError as exc:
            raise FeasibilityError(f"cannot inspect {label}: {current}") from exc
    try:
        info = path.lstat()
    except OSError as exc:
        raise FeasibilityError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise FeasibilityError(f"{label} is a symlink: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise FeasibilityError(f"{label} must be a directory: {path}")
    return path


def _read_json(path: Path, *, label: str) -> object:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise FeasibilityError(f"cannot read {label}: {path}") from exc
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except FeasibilityError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise FeasibilityError(f"{label} is not valid JSON: {exc}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _require_exact_keys(raw: object, expected: frozenset[str], *, label: str) -> dict[str, object]:
    if type(raw) is not dict:
        raise FeasibilityError(f"{label} must be a JSON object")
    actual = set(raw)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise FeasibilityError(f"{label} keys are not exact; missing={missing}, extra={extra}")
    return raw


def _nonnegative_int(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise FeasibilityError(f"{label} must be an integer, not a boolean or other type")
    if value < 0:
        raise FeasibilityError(f"{label} must be non-negative")
    return value


def _strict_bool(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise FeasibilityError(f"{label} must be a boolean")
    return value


def _load_constraints(path: str | os.PathLike[str]) -> dict[str, object]:
    raw = _read_json(_validate_existing_file(path, label="constraints JSON"), label="constraints JSON")
    values = _require_exact_keys(raw, CONSTRAINT_KEYS, label="constraints JSON")
    expected = {
        "schema": CONSTRAINTS_SCHEMA,
        "required_independent_families": REQUIRED_INDEPENDENT_FAMILIES,
        "maximum_final_submissions": MAXIMUM_FINAL_SUBMISSIONS,
        "reserved_final_submissions": RESERVED_FINAL_SUBMISSIONS,
        "authorized_nonfinal_research_submissions": AUTHORIZED_NONFINAL_RESEARCH_SUBMISSIONS,
        "currently_active_owned_exact_archives": CURRENTLY_ACTIVE_OWNED_EXACT_ARCHIVES,
        "currently_active_owned_independent_components": CURRENTLY_ACTIVE_OWNED_INDEPENDENT_COMPONENTS,
        "one_new_independent_family_per_submission_upper_bound": ONE_NEW_INDEPENDENT_FAMILY_PER_SUBMISSION_UPPER_BOUND,
        "external_exact_pair_intake_available": EXTERNAL_EXACT_PAIR_INTAKE_AVAILABLE,
    }
    result: dict[str, object] = {}
    for key, expected_value in expected.items():
        if key == "schema":
            if type(values[key]) is not str or values[key] != expected_value:
                raise FeasibilityError(f"constraints.schema must equal {expected_value}")
            result[key] = values[key]
        elif key == "external_exact_pair_intake_available":
            result[key] = _strict_bool(values[key], label=f"constraints.{key}")
        else:
            actual = _nonnegative_int(values[key], label=f"constraints.{key}")
            if actual != expected_value:
                raise FeasibilityError(f"constraints.{key} must equal {expected_value}")
            result[key] = actual

    if result["reserved_final_submissions"] > result["maximum_final_submissions"]:
        raise FeasibilityError("reserved final submissions exceed the maximum")
    if result["currently_active_owned_independent_components"] > result["currently_active_owned_exact_archives"]:
        raise FeasibilityError("owned independent components exceed owned exact archives")
    if result["external_exact_pair_intake_available"] is not False:
        raise FeasibilityError("external exact-pair intake must be disabled")
    return result


def _load_status(path: str | os.PathLike[str], *, required_family_count: int) -> dict[str, object]:
    raw = _read_json(_validate_existing_file(path, label="status JSON"), label="status JSON")
    if type(raw) is not dict:
        raise FeasibilityError("status JSON must be a JSON object")
    missing = sorted(STATUS_REQUIRED_KEYS - set(raw))
    if missing:
        raise FeasibilityError(f"status JSON is missing required keys: {missing}")
    if type(raw["schema"]) is not str or raw["schema"] != STATUS_SCHEMA:
        raise FeasibilityError(f"status.schema must equal {STATUS_SCHEMA}")
    values = raw
    result = {
        "prospective_required_family_count": _nonnegative_int(
            values["prospective_required_family_count"],
            label="status.prospective_required_family_count",
        ),
        "prospective_authenticated_independent_family_count": _nonnegative_int(
            values["prospective_authenticated_independent_family_count"],
            label="status.prospective_authenticated_independent_family_count",
        ),
        "paired_evidence_authenticated_unit_count": _nonnegative_int(
            values["paired_evidence_authenticated_unit_count"],
            label="status.paired_evidence_authenticated_unit_count",
        ),
        "prospective_production_verifier_available": _strict_bool(
            values["prospective_production_verifier_available"],
            label="status.prospective_production_verifier_available",
        ),
        "submission_authorized": _strict_bool(
            values["submission_authorized"], label="status.submission_authorized"
        ),
    }
    if result["prospective_required_family_count"] != required_family_count:
        raise FeasibilityError(
            "status prospective required family count contradicts constraints"
        )
    if result["prospective_authenticated_independent_family_count"] > required_family_count:
        raise FeasibilityError("authenticated independent family count exceeds required count")
    if result["paired_evidence_authenticated_unit_count"] > required_family_count:
        raise FeasibilityError("authenticated paired-unit count exceeds required count")
    return result


def audit_feasibility(
    constraints_path: str | os.PathLike[str],
    status_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Compute bounded feasibility counts without granting any authority."""

    constraints_file = _validate_existing_file(constraints_path, label="constraints JSON")
    status_file = _validate_existing_file(status_path, label="status JSON")
    constraints = _load_constraints(constraints_file)
    status = _load_status(
        status_file,
        required_family_count=int(constraints["required_independent_families"]),
    )
    required = int(constraints["required_independent_families"])
    authenticated_family_count = int(status["prospective_authenticated_independent_family_count"])
    authenticated_pair_count = int(status["paired_evidence_authenticated_unit_count"])
    authenticated_count = min(authenticated_family_count, authenticated_pair_count)
    current_potential_components = int(constraints["currently_active_owned_independent_components"])
    remaining_capacity = min(
        int(constraints["maximum_final_submissions"])
        - int(constraints["reserved_final_submissions"]),
        int(constraints["authorized_nonfinal_research_submissions"]),
    )
    families_per_submission = int(
        constraints["one_new_independent_family_per_submission_upper_bound"]
    )
    self_controlled_upper_bound = (
        authenticated_count
        + current_potential_components
        + remaining_capacity * families_per_submission
    )
    authenticated_shortfall = max(required - authenticated_count, 0)
    structural_shortfall = max(
        required - authenticated_count - current_potential_components,
        0,
    )
    external_pairs_needed = structural_shortfall
    if structural_shortfall == 0:
        nonfinal_submissions_needed = 0
    elif families_per_submission:
        nonfinal_submissions_needed = (
            structural_shortfall + families_per_submission - 1
        ) // families_per_submission
    else:
        nonfinal_submissions_needed = None

    mathematical_counts_satisfied = self_controlled_upper_bound >= required
    decision = DECISION_COUNTS_SATISFIED if mathematical_counts_satisfied else DECISION_INFEASIBLE

    # These are intentionally literals, rather than values copied from status.
    # A count audit cannot authenticate evidence or transition any authority.
    return {
        "schema": SCHEMA,
        "constraints_sha256": _sha256(constraints_file),
        "status_sha256": _sha256(status_file),
        "required_independent_family_count": required,
        "authenticated_count": authenticated_count,
        "authenticated_independent_family_count": authenticated_family_count,
        "authenticated_exact_pair_unit_count": authenticated_pair_count,
        "current_potential_owned_independent_components": current_potential_components,
        "remaining_nonfinal_submission_capacity": remaining_capacity,
        "maximum_self_controlled_independent_family_upper_bound_before_reserved_final_submission": self_controlled_upper_bound,
        "authenticated_shortfall": authenticated_shortfall,
        "structural_shortfall_even_if_current_owned_components_became_authenticated": structural_shortfall,
        "minimum_additional_independently_authenticated_external_pairs_needed": external_pairs_needed,
        "minimum_additional_nonfinal_submissions_needed_if_no_external_pairs": nonfinal_submissions_needed,
        "mathematical_counts_satisfied": mathematical_counts_satisfied,
        "production_feasible_now": False,
        "production_feasible_before_final_submission": False,
        "decision": decision,
        "authority": False,
        "candidate_authorized": False,
        "candidate_development_authorized": False,
        "holdout_access_authorized": False,
        "sealed_holdout_access_authorized": False,
        "production_authority": False,
        "production_authorized": False,
        "research_gate_open": False,
        "submission_authorized": False,
    }


def write_report_atomic(path: str | os.PathLike[str], report: Mapping[str, Any]) -> None:
    """Write deterministic report bytes with an atomic replacement."""

    output = _absolute_path(path, label="output JSON")
    _validate_existing_directory(output.parent, label="output parent")
    if output.exists() or output.is_symlink():
        try:
            info = output.lstat()
        except OSError as exc:
            raise FeasibilityError(f"cannot inspect output JSON: {output}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise FeasibilityError(f"output JSON is a symlink: {output}")
        if not stat.S_ISREG(info.st_mode):
            raise FeasibilityError(f"output JSON must be a regular file: {output}")

    data = canonical_json_bytes(report)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=str(output.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, output)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


# Descriptive aliases keep the pure API convenient for callers without adding
# another implementation path.
evaluate_feasibility = audit_feasibility
write_json_atomic = write_report_atomic


__all__ = [
    "CONSTRAINT_KEYS",
    "CONSTRAINTS_SCHEMA",
    "DECISION_COUNTS_SATISFIED",
    "DECISION_INFEASIBLE",
    "FeasibilityError",
    "SCHEMA",
    "STATUS_REQUIRED_KEYS",
    "STATUS_SCHEMA",
    "audit_feasibility",
    "canonical_json_bytes",
    "evaluate_feasibility",
    "render_json",
    "write_json_atomic",
    "write_report_atomic",
]
