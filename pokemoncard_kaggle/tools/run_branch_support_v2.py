#!/usr/bin/env python3
"""Run the frozen, outcome-blind branch_bridge_v2 Stage-A audit."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.branch_support_v2 import (  # noqa: E402
    EXECUTION_MANIFEST_DEPENDENCIES,
    evaluate_stage_a,
)
from evaluation_v2.stage_guard import (  # noqa: E402
    canonical_json,
    load_preregistration,
    require_outcome_blind,
    sha256_file,
    verify_execution_manifest,
)
from tools.build_branch_structural_rows import validate_structural_row  # noqa: E402
from tools.freeze_stage_execution import code_paths, dependency_versions  # noqa: E402


STAGE_CODE_PATHS = (
    ROOT / "evaluation_v2" / "__init__.py",
    ROOT / "evaluation_v2" / "schemas.py",
    ROOT / "evaluation_v2" / "branch_support_v2.py",
    ROOT / "evaluation_v2" / "branch_outcome.py",
    ROOT / "evaluation_v2" / "catalog_semantics.py",
    ROOT / "tools" / "build_branch_structural_rows.py",
    Path(__file__),
)
STAGE_LOCK_PATHS = (ROOT / "evaluation_v2" / "locks" / "branch_bridge_v2_stage_a_requirements.txt",)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line:
            raise ValueError(f"blank JSONL line at {line_number}")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"JSONL row {line_number} must be an object")
        values.append(value)
    if not values:
        raise ValueError("JSONL evidence is empty")
    return values


def load_stage_a_inputs(preregistration: dict[str, Any], *, root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    structural_record = preregistration["data"]["structural_rows"]
    schedule_record = preregistration["data"]["root_schedule"]
    structural_path = root / structural_record["path"]
    schedule_path = root / schedule_record["path"]
    rows = _read_jsonl(structural_path)
    schedule = _read_jsonl(schedule_path)
    require_outcome_blind(rows)
    require_outcome_blind(schedule)
    if len(rows) != int(structural_record["rows"]):
        raise ValueError("structural row count differs from preregistration")
    if len(schedule) != int(schedule_record["slots"]):
        raise ValueError("root schedule count differs from preregistration")
    for row in rows:
        validate_structural_row(row)
    return rows, schedule


def build_evidence(
    *,
    preregistration_path: Path,
    execution_manifest_path: Path,
    root: Path,
) -> dict[str, Any]:
    preregistration = load_preregistration(preregistration_path, root=root)
    versions = dependency_versions()
    expected_dependencies = dict(EXECUTION_MANIFEST_DEPENDENCIES)
    actual_dependencies = {"python": platform.python_version(), **versions}
    if actual_dependencies != expected_dependencies:
        raise ValueError("Stage-A runtime differs from frozen dependency versions")
    execution_manifest = json.loads(execution_manifest_path.read_text(encoding="utf-8"))
    verify_execution_manifest(
        execution_manifest,
        stage="stage_a",
        preregistration_path=preregistration_path,
        code_paths=code_paths(list(STAGE_CODE_PATHS)),
        lock_paths=STAGE_LOCK_PATHS,
        dependency_versions=versions,
    )
    rows, schedule = load_stage_a_inputs(preregistration, root=root)
    core = evaluate_stage_a(rows, schedule, preregistration)
    core_sha256 = hashlib.sha256(canonical_json(core).encode("ascii")).hexdigest()
    return {
        "schema": "branch_bridge_stage_a_evidence_v2",
        "experiment_id": "branch_bridge_v2",
        "preregistration_sha256": sha256_file(preregistration_path),
        "execution_manifest_sha256": sha256_file(execution_manifest_path),
        "structural_rows_sha256": preregistration["data"]["structural_rows"]["sha256"],
        "root_schedule_sha256": preregistration["data"]["root_schedule"]["sha256"],
        "core_sha256": core_sha256,
        "passed": bool(core.get("passed")),
        "core": core,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--execution-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = build_evidence(
        preregistration_path=args.preregistration,
        execution_manifest_path=args.execution_manifest,
        root=ROOT,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(canonical_json(evidence) + "\n", encoding="utf-8", newline="\n")
    summary = {
        "schema": evidence["schema"],
        "passed": evidence["passed"],
        "core_sha256": evidence["core_sha256"],
        "support_rates": evidence["core"]["support_rates"],
        "gate_checks": evidence["core"]["gate_checks"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
